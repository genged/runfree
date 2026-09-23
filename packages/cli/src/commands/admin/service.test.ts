import { describe, expect, test } from "vitest";
import type { DesiredServiceEntry } from "@runfree/runtime-contracts/desired-network-policy";

import type { Service } from "../../../../../scripts/services.ts";
import { formatServiceListTable, serviceListRows } from "./service.ts";

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
