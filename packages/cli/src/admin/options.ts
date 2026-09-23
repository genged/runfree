// Barrel for the admin enforcement modules (Phase 6 split of options.ts).
// options.ts was split into admin-core.ts (shared ambient state, policy/token
// stores, proxy runtime, token sync, reloadProxy) plus focused per-family
// enforcement modules. This barrel re-exports the full public surface so the
// command modules, runtime, and tests keep importing from "./admin/options.ts".

export {
  type CredentialClearSourceInput,
  type CredentialFieldsInput,
  type CredentialSetSourceInput,
  type CredentialStatusInput,
  type CredentialSyncInput,
  type DoctorInput,
  type DomainExplainInput,
  type DomainRemoveInput,
  type DomainRulesInput,
  type McpApproveInput,
  type McpConfigureInput,
  type McpExplainInput,
  type McpRulesInput,
  type McpRevokeInput,
  type RequestRuleInput,
  type ServiceConfigureInput,
  type ServiceDefineInput,
  type ServiceDisableInput,
  type ServiceEnableInput,
  type ServiceUndefineInput,
  type ServiceRecord,
  type ServiceRecords,
  type SourceAddCommandInput,
  type SourceAddJwtInput,
  type SourceNameInput,
  type TokenSourceSelection,
  convergeProxyPolicy,
  parseServiceRecords,
  reloadProxy,
  runAdminAction,
  serviceHostKeepReason,
  takeLastTokenSyncReceipts,
} from "./admin-core.ts";
export {
  domainExplainIntent,
  domainList,
} from "./domain-policy.ts";
export {
  bindDesiredCredentialSource,
  credentialClearSourceIntent,
  credentialSetSourceIntent,
  credentialSourceSelectionFromArgs,
  credentialStatus,
  credentialSyncIntent,
  revokeDesiredCredentialState,
} from "./credential-policy.ts";
export {
  sourceAddCommandIntent,
  sourceAddJwtIntent,
  sourceList,
  sourceRemoveIntent,
  sourceShowIntent,
} from "./source-policy.ts";
export {
  bindDesiredServiceCredentialSources,
  desiredServiceEntry,
  desiredServicePolicy,
  type DesiredServicePolicy,
  type DesiredServiceEnablePlan,
  type DesiredServiceConfigureOptions,
  planDesiredServiceEnable,
  promptForMissingServiceParameters,
  recordedAgentEnvNamesForServiceEntry,
  serviceConfigureIntent,
  serviceParameterStatus,
  serviceDefineIntent,
  serviceUndefineIntent,
} from "./service-policy.ts";
export {
  mcpApproveIntent,
  mcpConfigureIntent,
  mcpExplainIntent,
  mcpListIntent,
  mcpRulesIntent,
  mcpRevokeIntent,
  parseMcpAgent,
  parseMcpSource,
  prepareEffectiveRuntimeIntent,
} from "./mcp-admin.ts";
export {
  doctorIntent,
} from "./diagnostics.ts";
