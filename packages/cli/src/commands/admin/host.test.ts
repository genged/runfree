// The `host rules` show text (service host rules spec §4.10). The `<host>:`
// line is read by the live request-shape and git-provider tranches, so it is
// pinned byte for byte here as well.

import { describe, expect, test } from "vitest";

import { describeRuleFields, hostRulesShowLines } from "./host.ts";

describe("describeRuleFields", () => {
  test("names only the fields a rule sets", () => {
    expect(describeRuleFields({ gitPush: "deny", writeAction: "ask" })).toBe("gitPush=deny writeAction=ask");
    expect(describeRuleFields({
      methods: ["POST"],
      pathPrefixes: ["/oauth/token"],
      readPathPrefixes: ["/r/"],
      writePathPrefixes: ["/w/"],
      graphql: { endpoints: ["/api/graphql"], writeOps: "mutation" },
    })).toBe("methods=POST pathPrefixes=/oauth/token readPathPrefixes=/r/ writePathPrefixes=/w/ graphql=/api/graphql");
  });

  test("an absent or empty rule is none, not the spelled-out defaults", () => {
    expect(describeRuleFields(undefined)).toBe("none");
    expect(describeRuleFields({})).toBe("none");
  });
});

describe("hostRulesShowLines", () => {
  test("a service-owned host shows the service rule and the user setting apart", () => {
    expect(hostRulesShowLines({
      host: "github.com",
      scope: "project",
      owner: "service:github",
      ownerLayer: "project",
      enforced: { gitPush: "deny" },
      serviceRule: { gitPush: "write" },
      userSetting: { gitPush: "deny" },
    })).toEqual([
      "scope: project",
      "github.com: methods=all pathPrefixes=all gitPush=deny",
      "owner: service github (project)",
      "  service rule: gitPush=write",
      "  your setting: gitPush=deny",
    ]);
  });

  test("a service host with no rule from either side says none on both lines", () => {
    expect(hostRulesShowLines({
      host: "kept.example.com",
      scope: "local",
      owner: "service:review",
      ownerLayer: "local",
      userSetting: { writeAction: "deny" },
      enforced: { writeAction: "deny" },
    })).toEqual([
      "scope: checkout-local",
      "kept.example.com: methods=all pathPrefixes=all gitPush=allow writeAction=deny",
      "owner: service review (checkout-local)",
      "  service rule: none",
      "  your setting: writeAction=deny",
    ]);
  });

  test("a direct or rule-less host has no service lines", () => {
    expect(hostRulesShowLines({
      host: "api.example.com",
      scope: "project",
      owner: "direct",
      ownerLayer: "project",
      enforced: { methods: ["GET"] },
    })).toEqual([
      "scope: project",
      "api.example.com: methods=GET pathPrefixes=all gitPush=allow",
      "owner: direct (project)",
    ]);
    expect(hostRulesShowLines({ host: "open.example.com", scope: "project", owner: "none" })).toEqual([
      "scope: project",
      "open.example.com: none (all methods, all paths, git push allowed)",
      "owner: none",
    ]);
  });
});
