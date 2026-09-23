import { describe, expect, test } from "vitest";

import {
  CREDENTIAL_SCHEMES,
  DEFAULT_WRITE_ACTION,
  HTTP_METHODS,
  PolicyValidationError,
  READ_ONLY_METHODS,
  TOKEN_NAME_PATTERN,
  assertTokenName,
  credentialSchemeList,
  describeRequestRule,
  effectiveWriteAction,
  hostRulesCommand,
  httpMethodList,
  isCredentialScheme,
  isHttpMethod,
  isTokenName,
  shellQuoteToken,
  validateNetworkPolicy,
  type HttpMethod,
} from "./network-policy.ts";

function validationIssues(raw: unknown): string[] {
  try {
    validateNetworkPolicy(raw);
  } catch (error) {
    if (error instanceof PolicyValidationError) return error.issues;
    throw error;
  }
  return [];
}

describe("network policy token and credential-scheme validation", () => {
  test("exports token-name validation helpers used across runtime boundaries", () => {
    expect(TOKEN_NAME_PATTERN.source).toBe("^[a-z][a-z0-9_-]{0,63}$");
    expect(isTokenName("github")).toBe(true);
    expect(isTokenName("github-token_1")).toBe(true);
    expect(isTokenName("GitHub")).toBe(false);
    expect(isTokenName("../github")).toBe(false);
    expect(() => assertTokenName("github")).not.toThrow();
    expect(() => assertTokenName("../github")).toThrow("invalid token name: ../github");
  });

  test("exports credential-scheme helpers used by CLI and proxy consumers", () => {
    expect(CREDENTIAL_SCHEMES).toEqual(["bearer", "raw"]);
    expect(credentialSchemeList()).toBe("bearer, raw");
    expect(isCredentialScheme("bearer")).toBe(true);
    expect(isCredentialScheme("raw")).toBe(true);
    expect(isCredentialScheme("basic")).toBe(false);
  });

  test("exports HTTP method helpers mirroring the credential-scheme idiom", () => {
    expect(HTTP_METHODS).toEqual(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);
    expect(READ_ONLY_METHODS).toEqual(["GET", "HEAD", "OPTIONS"]);
    expect(httpMethodList()).toBe("GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE");
    expect(isHttpMethod("GET")).toBe(true);
    expect(isHttpMethod("DELETE")).toBe(true);
    expect(isHttpMethod("get")).toBe(false);
    expect(isHttpMethod("CONNECT")).toBe(false);
    expect(isHttpMethod("TRACE")).toBe(false);
    expect(isHttpMethod("FETCH")).toBe(false);
  });

  test("contract policy validation uses the shared token and scheme definitions", () => {
    expect(() => validateNetworkPolicy({
      hosts: ["api.example.com"],
      tokens: {
        "../bad": {
          description: "Bad token",
          credentials: [
            { host: "api.example.com", header: "Authorization", scheme: "basic" },
          ],
        },
      },
    })).toThrow(/token names must match \^\[a-z\]\[a-z0-9_-\]\{0,63\}\$/);
    expect(() => validateNetworkPolicy({
      hosts: ["api.example.com"],
      tokens: {
        good: {
          description: "Good token",
          credentials: [
            { host: "api.example.com", header: "Authorization", scheme: "basic" },
          ],
        },
      },
    })).toThrow(/scheme must be one of: bearer, raw/);
  });
});

describe("request-shape policy validation", () => {
  test("accepts normalized request rules and exposes them on the loaded policy", () => {
    const loaded = validateNetworkPolicy({
      hosts: ["api.github.com", "github.com", "pypi.org"],
      tokens: {},
      requests: {
        "pypi.org": { methods: ["GET", "HEAD"] },
        "api.github.com": { methods: ["GET", "HEAD", "OPTIONS"], pathPrefixes: ["/repos/"] },
        "github.com": { gitPush: "deny" },
      },
    });

    expect(loaded.requests).toEqual({
      "pypi.org": { methods: ["GET", "HEAD"] },
      "api.github.com": { methods: ["GET", "HEAD", "OPTIONS"], pathPrefixes: ["/repos/"] },
      "github.com": { gitPush: "deny" },
    });
    expect(loaded.raw.requests).toEqual(loaded.requests);
  });

  test("policies without requests expose allow-all shape semantics and omit the key", () => {
    const loaded = validateNetworkPolicy({ hosts: ["api.github.com"], tokens: {} });
    expect(loaded.requests).toEqual({});
    expect(loaded.raw.requests).toBeUndefined();
  });

  test("migrates legacy domains input to canonical hosts output", () => {
    const loaded = validateNetworkPolicy({ domains: ["api.github.com"], tokens: {} });

    expect(loaded.raw).toEqual({ hosts: ["api.github.com"], tokens: {} });
    expect(loaded.allowedHosts).toEqual(["api.github.com"]);
  });

  test("rejects ambiguous hosts plus legacy domains input", () => {
    expect(validationIssues({ hosts: ["api.github.com"], domains: ["raw.githubusercontent.com"], tokens: {} }))
      .toContain("policy must not define both hosts and legacy domains");
  });

  test("rejects rules for non-allowlisted or non-normalized hosts", () => {
    expect(validationIssues({
      hosts: ["api.github.com"],
      requests: { "unlisted.example.com": { methods: ["GET"] } },
    })).toContain("requests.unlisted.example.com has request rules but is not allowlisted");
    expect(validationIssues({
      hosts: ["api.github.com"],
      requests: { "API.GITHUB.COM": { methods: ["GET"] } },
    })).toContain("requests.API.GITHUB.COM must be stored lowercase");
  });

  test("rejects malformed methods with one issue per problem", () => {
    const issues = validationIssues({
      hosts: ["api.example.com"],
      requests: {
        "api.example.com": { methods: ["get", "CONNECT", "TRACE", "GET", "GET"] },
      },
    });
    expect(issues).toContain(`requests.api.example.com.methods[0] must be one of: ${httpMethodList()}`);
    expect(issues).toContain(`requests.api.example.com.methods[1] must be one of: ${httpMethodList()}`);
    expect(issues).toContain(`requests.api.example.com.methods[2] must be one of: ${httpMethodList()}`);
    expect(issues).toContain("requests.api.example.com.methods contains duplicate GET");
    expect(issues).toHaveLength(4);
  });

  test("rejects empty method and path arrays as fail-closed validation errors", () => {
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { methods: [] } },
    })).toContain("requests.api.example.com.methods must be non-empty; remove api.example.com from hosts instead");
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { pathPrefixes: [] } },
    })).toContain("requests.api.example.com.pathPrefixes must be non-empty when present");
  });

  test("rejects non-normalized, duplicate, and malformed path prefixes", () => {
    const issues = validationIssues({
      hosts: ["api.example.com"],
      requests: {
        "api.example.com": { pathPrefixes: ["v1/", "/v2/?x=1", "/v3/", "/v3/"] },
      },
    });
    expect(issues.some((issue) => issue.includes("pathPrefixes[0]") && issue.includes("must start with /"))).toBe(true);
    expect(issues.some((issue) => issue.includes("pathPrefixes[1]") && issue.includes("query or fragment"))).toBe(true);
    expect(issues).toContain("requests.api.example.com.pathPrefixes contains duplicate /v3/");
  });

  test("rejects unknown gitPush values, non-object rules, and empty rule objects", () => {
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { gitPush: "allow" } },
    })).toContain('requests.api.example.com.gitPush must be "deny" or "write" when present');
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": "deny" },
    })).toContain("requests.api.example.com must be an object");
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": {} },
    })).toContain("requests.api.example.com must define at least one of: methods, pathPrefixes, gitPush, writeAction, readPathPrefixes, writePathPrefixes, graphql");
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: [],
    })).toContain("requests must be an object when present");
  });

  test("accepts writeAction-only and graphql-only request entries as valid known fields", () => {
    const loaded = validateNetworkPolicy({
      hosts: ["api.example.com", "gql.example.com", "git.example.com"],
      tokens: {},
      requests: {
        "api.example.com": { writeAction: "ask" },
        "gql.example.com": { graphql: { endpoints: ["/graphql"], writeOps: "mutation" } },
        "git.example.com": { gitPush: "write", readPathPrefixes: ["/search/"], writePathPrefixes: ["/admin/"] },
      },
    });
    expect(loaded.requests["api.example.com"]).toEqual({ writeAction: "ask" });
    expect(loaded.requests["gql.example.com"]).toEqual({ graphql: { endpoints: ["/graphql"], writeOps: "mutation" } });
    expect(loaded.requests["git.example.com"]).toEqual({
      gitPush: "write",
      readPathPrefixes: ["/search/"],
      writePathPrefixes: ["/admin/"],
    });
  });

  test("rejects unknown request rule keys instead of ignoring them", () => {
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { writeAction: "ask", writeactions: "deny" } },
    })).toContain("requests.api.example.com.writeactions is not a known request rule field (known: methods, pathPrefixes, gitPush, writeAction, readPathPrefixes, writePathPrefixes, graphql)");
  });

  test("rejects malformed writeAction, graphql, and read/write path prefix values", () => {
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { writeAction: "block" } },
    })).toContain("requests.api.example.com.writeAction must be one of: allow, ask, deny");
    expect(validationIssues({
      hosts: ["api.example.com"],
      writeApproval: "block",
    })).toContain("writeApproval must be one of: allow, ask, deny");
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { graphql: { endpoints: ["/graphql"], writeOps: "all" } } },
    })).toContain('requests.api.example.com.graphql.writeOps must be "mutation"');
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { graphql: { endpoints: ["/graphql?x=1"], writeOps: "mutation" } } },
    }).some((issue) => issue.includes("graphql.endpoints[0]") && issue.includes("query or fragment"))).toBe(true);
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { graphql: { endpoints: ["/graph*"], writeOps: "mutation" } } },
    })).toContain("requests.api.example.com.graphql.endpoints must be exact paths without wildcards: /graph*");
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { graphql: { endpoints: [], writeOps: "mutation" } } },
    })).toContain("requests.api.example.com.graphql.endpoints must be non-empty when present");
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { graphql: { endpoints: ["/graphql"], writeOps: "mutation", parse: true } } },
    })).toContain("requests.api.example.com.graphql.parse is not a known graphql field (known: endpoints, writeOps)");
    expect(validationIssues({
      hosts: ["api.example.com"],
      requests: { "api.example.com": { readPathPrefixes: ["v1/"] } },
    }).some((issue) => issue.includes("readPathPrefixes[0]") && issue.includes("must start with /"))).toBe(true);
  });

  test("resolves effective write actions by precedence and folds the fields into the generation", () => {
    const base = { hosts: ["api.example.com", "other.example.com"], tokens: {} };
    const withoutWrite = validateNetworkPolicy(base);
    const hostRuled = validateNetworkPolicy({
      ...base,
      requests: { "api.example.com": { writeAction: "deny" } },
    });
    const defaulted = validateNetworkPolicy({ ...base, writeApproval: "ask" });
    const both = validateNetworkPolicy({
      ...base,
      writeApproval: "ask",
      requests: { "api.example.com": { writeAction: "allow" } },
    });

    expect(effectiveWriteAction(withoutWrite, "api.example.com")).toBe(DEFAULT_WRITE_ACTION);
    expect(effectiveWriteAction(hostRuled, "api.example.com")).toBe("deny");
    expect(effectiveWriteAction(hostRuled, "other.example.com")).toBe(DEFAULT_WRITE_ACTION);
    expect(effectiveWriteAction(defaulted, "api.example.com")).toBe("ask");
    expect(effectiveWriteAction(both, "api.example.com")).toBe("allow");
    expect(effectiveWriteAction(both, "other.example.com")).toBe("ask");

    // writeAction/writeApproval/graphql changes bump the generation; absent
    // fields keep the pre-tri-state generation for unchanged inputs.
    expect(hostRuled.generation).not.toBe(withoutWrite.generation);
    expect(defaulted.generation).not.toBe(withoutWrite.generation);
    expect(both.generation).not.toBe(defaulted.generation);
    const graphqlRuled = validateNetworkPolicy({
      ...base,
      requests: { "api.example.com": { graphql: { endpoints: ["/graphql"], writeOps: "mutation" } } },
    });
    expect(graphqlRuled.generation).not.toBe(withoutWrite.generation);
    // The firewall consumes allowedHosts only; the new fields never touch it.
    expect(graphqlRuled.allowedHosts).toEqual(withoutWrite.allowedHosts);
  });

  test("incorporates request rules into the policy generation deterministically", () => {
    const base = { hosts: ["api.example.com", "git.example.com"], tokens: {} };
    const withoutRequests = validateNetworkPolicy(base);
    const emptyRequests = validateNetworkPolicy({ ...base, requests: {} });
    const ruled = validateNetworkPolicy({
      ...base,
      requests: { "api.example.com": { methods: ["GET", "POST"] } },
    });
    const reordered = validateNetworkPolicy({
      ...base,
      requests: { "api.example.com": { methods: ["POST", "GET"] } },
    });
    const edited = validateNetworkPolicy({
      ...base,
      requests: { "api.example.com": { methods: ["GET"] } },
    });
    const moreRules = validateNetworkPolicy({
      ...base,
      requests: {
        "api.example.com": { methods: ["GET", "POST"] },
        "git.example.com": { gitPush: "deny" },
      },
    });

    // Absent (or empty) requests reproduce the pre-request-shape generation.
    expect(emptyRequests.generation).toBe(withoutRequests.generation);
    // Any rule change produces a new generation; rule-set-equal policies
    // converge regardless of stored ordering.
    expect(ruled.generation).not.toBe(withoutRequests.generation);
    expect(reordered.generation).toBe(ruled.generation);
    expect(edited.generation).not.toBe(ruled.generation);
    expect(moreRules.generation).not.toBe(ruled.generation);
    // The firewall consumes allowedHosts only, which request rules never touch.
    expect(ruled.allowedHosts).toEqual(withoutRequests.allowedHosts);
  });
});


describe("hostRulesCommand (rule-preserving remedies)", () => {
  test("reproduces the full current rule plus the widened method", () => {
    const command = hostRulesCommand(
      "api.github.com",
      { methods: ["GET", "HEAD"], pathPrefixes: ["/repos/"], gitPush: "deny", writeAction: "ask" },
      { method: "POST" },
    );
    expect(command.command).toBe(
      "runfree host rules api.github.com --method GET --method HEAD --method POST --request-path-prefix /repos/ --deny-git-push --write ask",
    );
    expect(command.resultingRule).toEqual({
      methods: ["GET", "HEAD", "POST"],
      pathPrefixes: ["/repos/"],
      gitPush: "deny",
      writeAction: "ask",
    });
    expect(command.unexpressible).toEqual([]);
  });

  test("round-trips a rule unchanged when nothing is widened", () => {
    const rule = { methods: ["GET"] as HttpMethod[], pathPrefixes: ["/a/", "/b/"], writeAction: "deny" as const };
    const command = hostRulesCommand("h.example", rule);
    expect(command.resultingRule).toEqual(rule);
    expect(command.argv).toEqual([
      "host", "rules", "h.example", "--method", "GET", "--request-path-prefix", "/a/", "--request-path-prefix", "/b/", "--write", "deny",
    ]);
  });

  test("does not duplicate an element that is already allowed", () => {
    const command = hostRulesCommand("h.example", { methods: ["GET", "POST"] }, { method: "POST" });
    expect(command.resultingRule).toEqual({ methods: ["GET", "POST"] });
  });

  test("widens the path prefix with a placeholder and keeps existing prefixes", () => {
    const command = hostRulesCommand("h.example", { pathPrefixes: ["/api/v2/"] }, { pathPrefix: "<prefix>" });
    expect(command.command).toBe("runfree host rules h.example --request-path-prefix /api/v2/ --request-path-prefix <prefix>");
  });

  test("names the fields the command cannot express", () => {
    const command = hostRulesCommand(
      "h.example",
      { methods: ["GET"], gitPush: "write", readPathPrefixes: ["/r/"], writePathPrefixes: ["/w/"], graphql: { endpoints: ["/graphql"], writeOps: "mutation" } },
      { method: "POST" },
    );
    expect(command.unexpressible).toEqual(["gitPush=write", "readPathPrefixes", "writePathPrefixes", "graphql"]);
    expect(command.command).toBe("runfree host rules h.example --method GET --method POST");
  });

  test("shell-quotes adversarial tokens instead of emitting them raw", () => {
    const command = hostRulesCommand("h.example", { pathPrefixes: ["/a b/", "/it's/", "/$(id)/", "/x;rm -rf/"] });
    expect(command.command).toBe(
      "runfree host rules h.example --request-path-prefix '/a b/' --request-path-prefix '/it'\\''s/' --request-path-prefix '/$(id)/' --request-path-prefix '/x;rm -rf/'",
    );
    expect(shellQuoteToken("plain-token.v1")).toBe("plain-token.v1");
    expect(shellQuoteToken("")).toBe("''");
    expect(shellQuoteToken("a\nb")).toBe("'a\nb'");
  });

  test("describeRequestRule renders the same line the CLI shows for a rule", () => {
    expect(describeRequestRule(undefined)).toBe("none (all methods, all paths, git push allowed)");
    expect(describeRequestRule({ methods: ["GET"], gitPush: "deny", writeAction: "ask" })).toBe(
      "methods=GET pathPrefixes=all gitPush=deny writeAction=ask",
    );
  });
});
