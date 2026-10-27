import { describe, expect, test } from "vitest";
import {
  type DesiredServiceEntry,
  validateDesiredNetworkPolicy,
  withRequiredDesiredNetworkPolicyVersion,
} from "@runfree/runtime-contracts/desired-network-policy";

import { SERVICES, type Service } from "../../../../../scripts/services.ts";
import { desiredServiceEntry } from "../../admin/service-policy.ts";
import { formatServiceExplanation, formatServiceListTable, planServiceRevisionChanges, serviceListRows, serviceRevisionRefusalLines } from "./service.ts";

function entry(revision: number, hosts: string[]): DesiredServiceEntry {
  return {
    revision,
    definitionDigest: "sha256:test",
    resolved: { hosts: hosts.map((host) => ({ host })) },
  } as unknown as DesiredServiceEntry;
}

function definition(id: string, revision: number, hosts: string[]): Service {
  return {
    id,
    label: id,
    revision,
    hosts: hosts.map((host) => ({ host })),
    detect: [],
    explanations: [],
  } as unknown as Service;
}

const registry: Record<string, Service> = {
  node: definition("node", 3, ["registry.npmjs.org", "nodejs.org"]),
  github: definition("github", 5, ["api.github.com", "github.com", "objects.githubusercontent.com"]),
  "user-internal-api": definition("user-internal-api", 1, ["api.internal.example"]),
};

describe("serviceListRows", () => {
  test("without --all lists only approved services", () => {
    const rows = serviceListRows({
      selected: { github: entry(5, ["api.github.com", "github.com"]) },
      localServiceIds: new Set(),
      registry,
      all: false,
    });
    expect(rows).toEqual([
      { id: "github", origin: "curated", state: "enabled", layer: "project", revision: 5, hosts: 2 },
    ]);
  });

  test("--all lists every registry service, marking enabled ones and their layer", () => {
    const rows = serviceListRows({
      selected: {
        github: entry(5, ["api.github.com", "github.com"]),
        "user-internal-api": entry(1, ["api.internal.example"]),
      },
      localServiceIds: new Set(["user-internal-api"]),
      registry,
      all: true,
    });
    expect(rows).toEqual([
      { id: "github", origin: "curated", state: "enabled", layer: "project", revision: 5, hosts: 2 },
      { id: "node", origin: "curated", state: "available", layer: "-", revision: 3, hosts: 2 },
      { id: "user-internal-api", origin: "user-defined", state: "enabled", layer: "local", revision: 1, hosts: 1 },
    ]);
  });

  test("--all keeps an enabled service whose definition left the registry", () => {
    const rows = serviceListRows({
      selected: { retired: entry(2, ["retired.example"]) },
      localServiceIds: new Set(),
      registry,
      all: true,
    });
    expect(rows.map((row) => row.id)).toEqual(["github", "node", "retired", "user-internal-api"]);
    expect(rows.find((row) => row.id === "retired")).toMatchObject({ state: "enabled", revision: 2, hosts: 1 });
  });

  test("returns nothing when neither approvals nor registry have services", () => {
    expect(serviceListRows({ selected: {}, localServiceIds: new Set(), registry: {}, all: true })).toEqual([]);
  });
});

describe("formatServiceListTable", () => {
  const rows = [
    { id: "agent-claude", origin: "curated", state: "enabled", layer: "project", revision: 1, hosts: 2 },
    { id: "appstore-connect", origin: "curated", state: "available", layer: "-", revision: 1, hosts: 1 },
    { id: "github", origin: "curated", state: "enabled", layer: "project", revision: 2, hosts: 6 },
  ] as const;

  test("--all renders space-aligned columns with a header", () => {
    expect(formatServiceListTable(rows, { all: true })).toBe([
      "SERVICE           ORIGIN   STATE      LAYER    REVISION  HOSTS",
      "agent-claude      curated  enabled    project  1         2",
      "appstore-connect  curated  available  -        1         1",
      "github            curated  enabled    project  2         6",
    ].join("\n"));
  });

  test("without --all omits the origin and state columns", () => {
    expect(formatServiceListTable([rows[0], rows[2]], { all: false })).toBe([
      "SERVICE       LAYER    REVISION  HOSTS",
      "agent-claude  project  1         2",
      "github        project  2         6",
    ].join("\n"));
  });

  test("never emits tab characters", () => {
    expect(formatServiceListTable(rows, { all: true })).not.toContain("\t");
  });
});

describe("planServiceRevisionChanges", () => {
  const empty = { version: 2 as const, hosts: [] as string[] };
  const layer = (services: Record<string, DesiredServiceEntry>) =>
    validateDesiredNetworkPolicy(withRequiredDesiredNetworkPolicyVersion({ ...empty, services }));

  test("an entry that differs from a fresh build only by its hostRules setting is current", () => {
    const fresh = desiredServiceEntry(SERVICES.github, { writeMode: "read-only" });
    const saved = { ...fresh, selection: { ...fresh.selection, hostRules: { "github.com": { gitPush: "deny" as const } } } };
    const plan = planServiceRevisionChanges({ project: layer({ github: saved }), local: empty }, SERVICES, {});
    expect(plan.lines).toEqual(["github (project): current"]);
    expect(plan.changes).toEqual([]);
  });

  test("a revision change carries the saved hostRules into the next entry", () => {
    const stale = desiredServiceEntry({ ...SERVICES.node, revision: 1 }, { hostRules: { "registry.npmjs.org": { writeAction: "deny" } } });
    const plan = planServiceRevisionChanges({ project: empty, local: layer({ node: stale }) }, SERVICES, {});
    expect(plan.lines[0]).toBe(`node (local): revision 1 -> ${SERVICES.node.revision}`);
    expect(plan.changes).toHaveLength(1);
    expect(plan.changes[0].refusals).toEqual([]);
    expect(plan.changes[0].entry.selection?.hostRules).toEqual({ "registry.npmjs.org": { writeAction: "deny" } });
    expect(plan.changes[0].entry.revision).toBe(SERVICES.node.revision);
    expect(plan.proposed.local.version).toBe(4);
    expect(() => validateDesiredNetworkPolicy(plan.proposed.local)).not.toThrow();
  });

  test("lists a refusal for a saved setting on a host the new revision removes", () => {
    const old: Service = {
      ...SERVICES.node,
      revision: 1,
      hosts: [...SERVICES.node.hosts, { host: "gone.npm.example" }],
    };
    const stale = desiredServiceEntry(old, { hostRules: { "gone.npm.example": { writeAction: "deny" } } });
    const plan = planServiceRevisionChanges({ project: layer({ node: stale }), local: empty }, SERVICES, {});
    expect(plan.changes.map((change) => change.refusals)).toEqual([[
      `service node revision ${SERVICES.node.revision} no longer allows gone.npm.example, which has a host rule setting; remove it first with: runfree host rules gone.npm.example --clear --service node`,
    ]]);
  });

  test("lists every refusal of every conflicting change, not only the first", () => {
    const old: Service = {
      ...SERVICES.node,
      revision: 1,
      hosts: [...SERVICES.node.hosts, { host: "gone.npm.example" }, { host: "gone2.npm.example" }],
    };
    const projectStale = desiredServiceEntry(old, { hostRules: { "gone.npm.example": { writeAction: "deny" } } });
    const localStale = desiredServiceEntry(old, {
      hostRules: { "gone.npm.example": { writeAction: "deny" }, "gone2.npm.example": { writeAction: "ask" } },
    });
    const plan = planServiceRevisionChanges({ project: layer({ node: projectStale }), local: layer({ node: localStale }) }, SERVICES, {});
    const gone = (host: string, local: boolean) =>
      `  refuses: service node revision ${SERVICES.node.revision} no longer allows ${host}, which has a host rule setting; remove it first with: runfree host rules ${host} --clear --service node${local ? " --local" : ""}`;
    expect(serviceRevisionRefusalLines(plan.changes)).toEqual([
      gone("gone.npm.example", false),
      gone("gone.npm.example", true),
      gone("gone2.npm.example", true),
    ]);
  });
});

describe("formatServiceExplanation", () => {
  test("strips terminal escapes from author-supplied text of a user-defined service", () => {
    const svc = {
      ...definition("user-acme", 1, ["api.acme.example"]),
      label: "Acme\u001b[2J",
      explanations: ["setup\u001b[31m step"],
      credential: {
        tokenName: "user-acme",
        tokenDescription: "Acme\u0007 token",
        agentEnv: ["ACME_TOKEN"],
        credentials: [{ host: "api.acme.example", header: "Authorization", scheme: "bearer" }],
      },
    } as unknown as Service;
    const text = formatServiceExplanation({ id: "user-acme", definition: svc, enabled: undefined, parameterValues: {} }).join("\n");
    expect(text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/);
    expect(text).toContain("origin: user-defined");
    expect(text).toContain("  - setup step");
    expect(text).toContain("  api.acme.example -> Authorization (bearer)");
  });

  test("an enabled entry behind the registry names the diff, and a vanished definition keeps the entry", () => {
    const enabled = { entry: entry(2, ["registry.npmjs.org"]), layer: "local" as const };
    const behind = formatServiceExplanation({ id: "node", definition: registry.node, enabled, parameterValues: {} });
    expect(behind).toContain("state: enabled (local layer), approved revision 2");
    expect(behind).toContain("current revision: 3; review with: runfree service diff");

    const vanished = formatServiceExplanation({ id: "mystery", definition: undefined, enabled, parameterValues: {} });
    expect(vanished).toContain("definition: unavailable; approved semantics retained");
    expect(vanished).not.toContain("notes:");
  });

  test("parameter values are reported only for an enabled service", () => {
    const svc = SERVICES["apple-ads"];
    const available = formatServiceExplanation({ id: "apple-ads", definition: svc, enabled: undefined, parameterValues: {} });
    expect(available.some((line) => line.startsWith("  --param client-id=<value> or APPLE_ADS_CLIENT_ID:") && !line.endsWith("; unset"))).toBe(true);
    const enabled = formatServiceExplanation({
      id: "apple-ads",
      definition: svc,
      enabled: { entry: entry(svc.revision, ["api.searchads.apple.com"]), layer: "project" },
      parameterValues: { "client-id": "set" },
    });
    expect(enabled.some((line) => line.endsWith("; set"))).toBe(true);
  });
});
