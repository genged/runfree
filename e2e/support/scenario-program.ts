import type { ScenarioId } from "./evidence-contract.ts";

export type ProgramStatus = "Planned" | "Partial" | "Implemented" | "Implemented-failing" | "Blocked";

export type ProgramScenario = Readonly<{
  id: Exclude<ScenarioId, "HARNESS">;
  title: string;
  status: ProgramStatus;
}>;

const entries = [
  ["LH-01", "Installed Artifact And Command Contract", "Partial"],
  ["LH-02", "First Project, Wizard, And Workspace Selection", "Partial"],
  ["LH-03", "Config Migration, Interruption, And Downgrade Boundary", "Partial"],
  ["LH-04", "Desired, Approved, And Effective Policy Lifecycle", "Partial"],
  ["LH-05", "Exact Hosts, Request Rules, And Denial Diagnostics", "Partial"],
  ["LH-06", "Host-Owned Credential Source Lifecycle", "Partial"],
  ["LH-07", "Credential Destinations, Rotation, And Revocation", "Partial"],
  ["LH-08", "Curated Service Lifecycle And Shared Ownership", "Partial"],
  ["LH-09", "User-Defined Service Evolution", "Partial"],
  ["LH-10", "Project Image Approval And Pre-Sandbox Build Boundary", "Partial"],
  ["LH-11", "Runtime Start, Reuse, Convergence, And Component Upgrade", "Partial"],
  ["LH-12", "Built-In Agents, Custom Agents, And Shell Sessions", "Partial"],
  ["LH-13", "Concurrent Session Admission And Lease Continuity", "Partial"],
  ["LH-14", "Write Approval Across Time, Sessions, And Restarts", "Planned"],
  ["LH-15", "Time-Boxed Network Audit Onboarding", "Partial"],
  ["LH-16", "Protocol And Request-Shape Enforcement", "Partial"],
  ["LH-17", "MCP Import, Credentials, OAuth, And Tool Approval", "Partial"],
  ["LH-18", "Dependency Overlay Lifecycle And Drift", "Planned"],
  ["LH-19", "Interrupted Session Inventory And Exact Resume", "Partial"],
  ["LH-20", "Rebuild, Stop, Destroy, And Stale-State Recovery", "Partial"],
  ["LH-21", "VNC Sidecar Lifecycle", "Planned"],
  ["LH-22", "Host-To-Agent Port Forward Lifecycle", "Planned"],
  ["LH-23", "Inbox Import, Read-Only Delivery, And Cleanup", "Partial"],
  ["LH-24", "Git Worktrees, Checkout-Local Policy, And Project Identity", "Planned"],
  ["LH-25", "Embedded Assets, Binary Upgrade, And Native Release", "Planned"],
  ["LH-26", "Parser, Filesystem, Output, And Secret Failure Matrix", "Partial"],
  ["LH-27", "One Developer Week", "Planned"],
  ["LH-28", "Real Agent And Provider Compatibility", "Planned"],
  ["LH-29", "Native Installation, Upgrade, And Reinstallation", "Planned"],
  ["LH-30", "Concurrent Projects And Shared Host State", "Planned"],
  ["LH-31", "Host And Docker Resource Exhaustion", "Planned"],
  ["LH-32", "Docker Backend, Daemon, And Network Chaos", "Planned"],
  ["LH-33", "Adversarial Credential Source Output And Rotation", "Planned"],
  ["LH-34", "OAuth And MCP Adversarial Lifecycle", "Planned"],
  ["LH-35", "Extended TLS, DNS, HTTP, And WebSocket Cases", "Planned"],
  ["LH-36", "Cross-Command Race Matrix", "Planned"],
  ["LH-37", "Structured Input Fuzzing And Bounds", "Planned"],
  ["LH-38", "Extended Soak, Churn, And Leak Detection", "Planned"],
] as const satisfies readonly (readonly [ProgramScenario["id"], string, ProgramStatus])[];

export const PROGRAM_SCENARIOS: readonly ProgramScenario[] = Object.freeze(entries.map(([id, title, status]) =>
  Object.freeze({ id, title, status })));

export const BLOCKED_WORK = Object.freeze([
  Object.freeze({
    scenarioIds: Object.freeze([
      "LH-02", "LH-09", "LH-12", "LH-14", "LH-17", "LH-18",
      "LH-19", "LH-20", "LH-21", "LH-26", "LH-27", "LH-34",
    ]),
    layer: "T",
    reason: "Pseudo-terminal scenarios require maintainer approval for a maintained PTY dependency.",
  }),
]);

export function validateProgramScenarios(scenarios: readonly ProgramScenario[] = PROGRAM_SCENARIOS): void {
  if (scenarios.length !== 38) throw new Error(`long-horizon program must contain 38 scenarios, found ${scenarios.length}`);
  const ids = scenarios.map((scenario) => scenario.id);
  if (new Set(ids).size !== ids.length) throw new Error("long-horizon program repeats a scenario ID");
  for (let index = 0; index < scenarios.length; index += 1) {
    const expected = `LH-${String(index + 1).padStart(2, "0")}`;
    if (scenarios[index]?.id !== expected) {
      throw new Error(`long-horizon program expected ${expected} at position ${index + 1}`);
    }
  }
}
