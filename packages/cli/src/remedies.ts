// The remedy registry (output contract D4).
//
// Every `runfree ...` command the host CLI prints as a next step is rendered
// here, never hand-written at the emitting site. `scripts/emitted-commands.test.ts`
// parses each registry rendering under the real yargs app, so a remedy that
// names a command or flag that does not exist fails the gate instead of
// reaching an operator.
//
// Decision 2 (settled 2026-09-02): rebuild hints use the interactive form.
// `--yes` appears only where the surrounding workflow already selected
// unattended operation; a non-TTY alone is not consent to a destructive
// default, so `rebuildUnattended` is reserved for those callers.

export const remedy = {
  up: (): string => "runfree up",
  stop: (): string => "runfree stop",
  rebuild: (): string => "runfree rebuild",
  rebuildUnattended: (): string => "runfree rebuild --yes",
  destroyForce: (): string => "runfree destroy --force",
  doctor: (): string => "runfree doctor",
  sessions: (): string => "runfree sessions",
  approvals: (): string => "runfree approvals",
  approvalsWatch: (): string => "runfree approvals --watch",
  policyStatus: (): string => "runfree policy status",
  policyReview: (layer: "project" | "local"): string => `runfree policy review --${layer}`,
  policyApprove: (layer: "project" | "local"): string => `runfree policy approve --${layer}`,
  policyUseApproved: (): string => "runfree policy use-approved",
  hostAdd: (host: string, options: { local?: boolean } = {}): string => `runfree host add ${host}${options.local ? " --local" : ""}`,
  hostExplain: (host: string): string => `runfree host explain ${host}`,
  hostRules: (host: string): string => `runfree host rules ${host}`,
  serviceEnable: (id: string): string => `runfree service enable ${id}`,
  // `sourceArgs` repeats the credential-source flags the operator already gave
  // ("--from-source src"), so the rendered command is the one they ran plus
  // the missing parameter.
  serviceEnableParam: (id: string, key: string, options: { sourceArgs?: string } = {}): string =>
    `runfree service enable ${id}${options.sourceArgs ? ` ${options.sourceArgs}` : ""} --param ${key}=<value>`,
  serviceEnableFromItem: (id: string): string => `runfree service enable ${id} --from-1password-item op://<vault>/<item>`,
  serviceEnableHelp: (): string => "runfree service enable --help",
  serviceExplain: (id: string): string => `runfree service explain ${id}`,
  credentialAdd: (name: string, host: string, source: string): string =>
    `runfree credential add ${name} --host ${host} --from-source ${source}`,
  credentialUnlink: (name: string, host: string): string => `runfree credential unlink ${name} --host ${host}`,
  imageApproveContext: (): string => "runfree image approve-context",
  imageInit: (): string => "runfree image init",
  destroy: (): string => "runfree destroy",
  runtimeReloadPolicy: (): string => "runfree runtime reload-policy",
  forwardStatus: (): string => "runfree forward status",
  forwardStop: (): string => "runfree forward stop",
  statusVerbose: (): string => "runfree status --verbose",
  help: (): string => "runfree help",
  init: (): string => "runfree init",
} as const;

// One sample rendering per registry entry, for the parse gate.
export function sampleRemedyRenderings(): string[] {
  return [
    remedy.up(),
    remedy.stop(),
    remedy.rebuild(),
    remedy.rebuildUnattended(),
    remedy.destroyForce(),
    remedy.doctor(),
    remedy.sessions(),
    remedy.approvals(),
    remedy.approvalsWatch(),
    remedy.policyStatus(),
    remedy.policyReview("project"),
    remedy.policyReview("local"),
    remedy.policyApprove("project"),
    remedy.policyUseApproved(),
    remedy.hostAdd("api.example.com"),
    remedy.hostAdd("api.example.com", { local: true }),
    remedy.hostExplain("api.example.com"),
    remedy.hostRules("api.example.com"),
    remedy.serviceEnable("github"),
    remedy.serviceEnableParam("apple-ads", "client-id"),
    remedy.serviceEnableParam("apple-ads", "client-id", { sourceArgs: "--from-source src" }),
    remedy.serviceEnableFromItem("apple-ads"),
    remedy.serviceEnableHelp(),
    remedy.serviceExplain("github"),
    remedy.credentialAdd("github", "api.github.com", "github-cli"),
    remedy.credentialUnlink("github", "api.github.com"),
    remedy.imageApproveContext(),
    remedy.imageInit(),
    remedy.destroy(),
    remedy.runtimeReloadPolicy(),
    remedy.forwardStatus(),
    remedy.forwardStop(),
    remedy.statusVerbose(),
    remedy.help(),
    remedy.init(),
  ];
}
