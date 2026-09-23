import path from "node:path";

import { describe, expect, test } from "vitest";

import { projectIdentity, sanitizeProjectName } from "./project-identity.ts";

describe("project identity", () => {
  test("derives a visible project path from the project root basename", () => {
    expect(projectIdentity(path.join("/tmp", "payments-api"))).toEqual({
      name: "payments-api",
      containerRoot: "/workspaces/payments-api",
      compatRoot: "/workspace",
    });
  });

  test("uses sanitized configured project names for visible paths", () => {
    expect(sanitizeProjectName("  Client / API: staging  ")).toBe("Client-API-staging");
    expect(sanitizeProjectName("../..")).toBe("project");
    expect(sanitizeProjectName("a".repeat(80))).toBe("a".repeat(64));
    expect(projectIdentity("/private/path/repo", { project: { name: "  Client / API  " } }).containerRoot)
      .toBe("/workspaces/Client-API");
  });
});
