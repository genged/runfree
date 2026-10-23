import { describe, expect, test } from "vitest";
import {
  type DesiredServiceEntry,
  validateDesiredNetworkPolicy,
  withRequiredDesiredNetworkPolicyVersion,
} from "@runfree/runtime-contracts/desired-network-policy";

import { SERVICES, type Service } from "../../../../../scripts/services.ts";
import { desiredServiceEntry } from "../../admin/service-policy.ts";
import { formatServiceListTable, planServiceRevisionChanges, serviceListRows } from "./service.ts";

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
});
