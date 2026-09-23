import { describe, expect, test } from "vitest";

import { compileDesiredPolicies } from "./compiler.ts";
import { migrateLegacyDesiredPolicy } from "./legacy-migration.ts";

describe("legacy desired-policy migration", () => {
  test("preserves exact direct network authority and moves write posture", () => {
    const migrated = migrateLegacyDesiredPolicy({
      configWriteApproval: "ask",
      policy: {
        hosts: ["example.com"],
        requests: { "example.com": { methods: ["GET"] } },
      },
    });
    expect(migrated).toMatchObject({ version: 2, hosts: ["example.com"], writeApproval: "ask" });
    expect(compileDesiredPolicies({ project: migrated, local: { version: 2, hosts: [] } }).policy)
      .toMatchObject({ hosts: ["example.com"], requests: { "example.com": { methods: ["GET"] } }, writeApproval: "ask" });
  });

  test("records a recognized service without claiming ambiguous direct authority", () => {
    const migrated = migrateLegacyDesiredPolicy({
      policy: {
        hosts: ["files.pythonhosted.org", "pypi.org", "unrelated.example"],
        requests: { "pypi.org": { methods: ["GET"] } },
      },
      services: { python: { revision: 1 } },
    });
    expect(migrated.services?.python).toMatchObject({
      revision: 1,
      resolved: { hosts: ["files.pythonhosted.org", "pypi.org"] },
    });
    expect(migrated.hosts).toEqual(["files.pythonhosted.org", "pypi.org", "unrelated.example"]);
    expect(migrated.requests).toEqual({ "pypi.org": { methods: ["GET"] } });
    const compiled = compileDesiredPolicies({ project: migrated, local: { version: 2, hosts: [] } }).policy;
    expect(compiled.hosts).toEqual(["files.pythonhosted.org", "pypi.org", "unrelated.example"]);
    expect(compiled.requests).toEqual({ "pypi.org": { methods: ["GET"] } });

    const withoutService = structuredClone(migrated);
    delete withoutService.services?.python;
    expect(compileDesiredPolicies({ project: withoutService, local: { version: 2, hosts: [] } }).policy)
      .toEqual(compiled);
  });

  test("preserves a matching credential-bearing service token as ambiguous direct authority", () => {
    const migrated = migrateLegacyDesiredPolicy({
      policy: {
        hosts: ["api.github.com", "github.com", "uploads.github.com"],
        tokens: {
          github: {
            description: "GitHub token",
            allowAnonymous: true,
            credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
          },
        },
      },
      services: { github: { revision: 2 } },
    });

    expect(migrated.services?.github?.resolved.tokens).toBeUndefined();
    expect(migrated.services?.github?.resolved.agentEnv).toBeUndefined();
    expect(migrated.tokens?.github).toBeDefined();
    const compiled = compileDesiredPolicies({ project: migrated, local: { version: 2, hosts: [] } }).policy;
    const withoutService = structuredClone(migrated);
    delete withoutService.services?.github;
    expect(compileDesiredPolicies({ project: withoutService, local: { version: 2, hosts: [] } }).policy)
      .toEqual(compiled);
  });

  test("migrates a service recorded at a superseded revision without changing authority", () => {
    const migrated = migrateLegacyDesiredPolicy({
      policy: { hosts: ["api.github.com", "github.com"] },
      services: { github: { revision: 1 } },
    });
    // The recorded revision survives verbatim so `service diff` still reports
    // the gap to the current registry revision instead of silently adopting it.
    expect(migrated.services?.github).toMatchObject({
      revision: 1,
      resolved: { hosts: ["api.github.com", "github.com"] },
    });
    expect(compileDesiredPolicies({ project: migrated, local: { version: 2, hosts: [] } }).policy.hosts)
      .toEqual(["api.github.com", "github.com"]);
  });

  test("keeps unprovable service records as direct hosts instead of refusing to migrate", () => {
    // Every record shape the curated registry cannot prove. `runfree init` is
    // the only path to config v4, so refusing any of these would strand the
    // project with no way forward.
    const unprovable: Array<[string, Record<string, unknown>, string]> = [
      ["ahead of the registry", { github: { revision: 99 } }, "ahead of the available revision"],
      ["user-defined", { "user-internal": { revision: 1, digest: `sha256:${"a".repeat(64)}`, hosts: ["github.com"] } }, "no pinned definition"],
      ["retired from the registry", { "retired-thing": { revision: 1 } }, "no pinned definition"],
    ];
    for (const [label, services, expected] of unprovable) {
      const notes: string[] = [];
      const migrated = migrateLegacyDesiredPolicy({
        onNote: (note) => notes.push(note),
        policy: { hosts: ["api.github.com", "github.com"] },
        services,
      });
      // Authority is unchanged; only the service association is dropped.
      expect(migrated.hosts, label).toEqual(["api.github.com", "github.com"]);
      expect(migrated.services, label).toBeUndefined();
      expect(notes.join("\n"), label).toMatch(new RegExp(expected));
      expect(notes.join("\n"), label).toMatch(/runfree service enable/);
    }
  });

  test("keeps a service whose current hosts left the enforced policy as direct hosts", () => {
    const notes: string[] = [];
    const migrated = migrateLegacyDesiredPolicy({
      onNote: (note) => notes.push(note),
      policy: { hosts: ["unrelated.example"] },
      services: { python: { revision: 1 } },
    });
    expect(migrated.hosts).toEqual(["unrelated.example"]);
    expect(migrated.services).toBeUndefined();
    expect(notes.join("\n")).toMatch(/none of its current hosts are in the enforced policy/);
  });

  test("accepts already-migrated strict v2 input idempotently", () => {
    expect(migrateLegacyDesiredPolicy({ policy: { version: 2, hosts: [] } }))
      .toEqual({ version: 2, hosts: [] });
  });
});
