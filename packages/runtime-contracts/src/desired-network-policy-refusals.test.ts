import { describe, expect, test } from "vitest";

import {
  canonicalDesiredNetworkPolicy,
  DesiredNetworkPolicyValidationError,
  desiredNetworkPolicyV3Features,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "./desired-network-policy.ts";

const digest = `sha256:${"a".repeat(64)}`;
const P = "services.svc.resolved.oauth.service:svc";
const S = "services.svc";

function svc(resolvedExtra: Record<string, unknown>, entryExtra: Record<string, unknown> = {}, id = "svc") {
  return {
    version: 2,
    hosts: [],
    services: {
      [id]: {
        revision: 1,
        definitionDigest: digest,
        resolved: { hosts: ["api.example.com"], ...resolvedExtra },
        ...entryExtra,
      },
    },
  };
}

function prov(p: Record<string, unknown>) {
  return svc({
    oauth: {
      "service:svc": {
        resourceHost: "api.example.com",
        tokenEndpoints: [{ host: "auth.example.com", path: "/token" }],
        ...p,
      },
    },
  });
}

const seed = { field: "refresh_token", envVar: "R_TOK", tokenName: "svc", description: "refresh" };
const param = { key: "a", envVar: "A", description: "a parameter" };

function issuesOf(raw: unknown): string[] {
  try {
    validateDesiredNetworkPolicy(raw);
  } catch (error) {
    expect(error).toBeInstanceOf(DesiredNetworkPolicyValidationError);
    return (error as DesiredNetworkPolicyValidationError).issues;
  }
  throw new Error("expected the policy to be refused");
}

function providerOf(raw: unknown) {
  return validateDesiredNetworkPolicy(raw).services?.svc?.resolved.oauth?.["service:svc"];
}

type Case = [name: string, raw: unknown, issues: string[]];

function refusals(title: string, cases: Case[]): void {
  test.each(cases)(`${title}: %s`, (_name, raw, issues) => {
    expect(issuesOf(raw)).toEqual(issues);
  });
}

describe("desired network policy OAuth providers", () => {
  test("B1 accepts a provider and canonicalizes its endpoints", () => {
    const provider = {
      resourceHost: "api.example.com",
      tokenEndpoints: [{ host: "b.example.com", path: "/t" }, { host: "a.example.com", path: "/t" }],
      registrationEndpoints: [{ host: "a.example.com", path: "/reg" }],
      resourcePathPrefix: "/v1/",
      seeds: [seed],
    };
    const raw = svc({ oauth: { "service:svc": provider } });
    expect(providerOf(raw)).toEqual({
      resourceHost: "api.example.com",
      tokenEndpoints: [{ host: "a.example.com", path: "/t" }, { host: "b.example.com", path: "/t" }],
      resourcePathPrefix: "/v1/",
      registrationEndpoints: [{ host: "a.example.com", path: "/reg" }],
      seeds: [seed],
    });

    const reversed = Object.fromEntries(Object.entries(provider).reverse());
    const reversedRaw = svc({ oauth: { "service:svc": reversed } });
    expect(Object.keys(reversed)).not.toEqual(Object.keys(provider));
    expect(canonicalDesiredNetworkPolicy(reversedRaw as DesiredNetworkPolicyJson))
      .toBe(canonicalDesiredNetworkPolicy(raw as DesiredNetworkPolicyJson));
  });

  test("B1 keeps a client_id passthrough", () => {
    expect(providerOf(prov({ passthrough: [{ field: "client_id", envVar: "X" }] }))?.passthrough)
      .toEqual([{ field: "client_id", envVar: "X" }]);
  });

  refusals("B2 provider shape", [
    ["oauth is an array", svc({ oauth: [] }), [`${S}.resolved.oauth must be an object`]],
    ["provider is a string", svc({ oauth: { "service:svc": "x" } }), [`${P} must be an object`]],
    ["resourceHost not a string", prov({ resourceHost: 5 }), [`${P}.resourceHost must be a string`]],
    ["resourceHost not lowercase", prov({ resourceHost: "API.Example.com" }), [`${P}.resourceHost must be stored as api.example.com`]],
    ["resourceHost invalid", prov({ resourceHost: "bad host!" }), [`${P}: expected fully-qualified hostname`]],
    ["resourcePathPrefix not a string", prov({ resourcePathPrefix: 7 }), [`${P}: resourcePathPrefix must be a string`]],
    ["resourcePathPrefix relative", prov({ resourcePathPrefix: "v1" }), [`${P}: pathPrefix must start with /`]],
    ["unknown field", prov({ clientSecret: "s" }), [
      `${P}.clientSecret is not a known field (known: passthrough, registrationEndpoints, resourceHost, resourcePathPrefix, seeds, tokenEndpoints)`,
    ]],
  ]);

  const ep = { host: "a.example.com", path: "/t" };
  refusals("B3 endpoints", [
    ["not an array", prov({ tokenEndpoints: "x" }), [`${P}.tokenEndpoints must be an array`]],
    ["entry not an object", prov({ tokenEndpoints: ["x"] }), [`${P}.tokenEndpoints[0] must be an object`]],
    ["path missing", prov({ tokenEndpoints: [{ host: "a.example.com" }] }), [`${P}.tokenEndpoints[0].host and .path must be strings`]],
    ["unknown key", prov({ tokenEndpoints: [{ ...ep, method: "POST" }] }), [
      `${P}.tokenEndpoints[0].method is not a known field (known: host, path)`,
    ]],
    ["host not lowercase", prov({ tokenEndpoints: [{ host: "A.example.com", path: "/t" }] }), [
      `${P}.tokenEndpoints[0].host must be stored as a.example.com`,
    ]],
    ["path relative", prov({ tokenEndpoints: [{ host: "a.example.com", path: "t" }] }), [
      `${P}.tokenEndpoints[0]: pathPrefix must start with /`,
    ]],
    ["host invalid", prov({ tokenEndpoints: [{ host: "bad host", path: "/t" }] }), [
      `${P}.tokenEndpoints[0]: expected fully-qualified hostname`,
    ]],
    ["duplicate endpoint", prov({ tokenEndpoints: [ep, { ...ep }] }), [`${P}.tokenEndpoints must not contain duplicate endpoints`]],
    ["registrationEndpoints not an array", prov({ registrationEndpoints: {} }), [`${P}.registrationEndpoints must be an array`]],
  ]);

  refusals("B4 seeds", [
    ["not an array", prov({ seeds: {} }), [`${P}.seeds must be an array`]],
    ["entry not an object", prov({ seeds: [1] }), [`${P}.seeds[0] must be an object`]],
    ["access_token field", prov({ seeds: [{ ...seed, field: "access_token" }] }), [`${P}.seeds[0] is malformed`]],
    ["bad envVar", prov({ seeds: [{ ...seed, envVar: "1R" }] }), [`${P}.seeds[0] is malformed`]],
    ["bad tokenName", prov({ seeds: [{ ...seed, tokenName: "Svc" }] }), [`${P}.seeds[0] is malformed`]],
    ["blank description", prov({ seeds: [{ ...seed, description: "  " }] }), [`${P}.seeds[0] is malformed`]],
    ["unknown key", prov({ seeds: [{ ...seed, value: "secret" }] }), [
      `${P}.seeds[0].value is not a known field (known: description, envVar, field, tokenName)`,
    ]],
  ]);

  test("B4 accepts a client_secret seed", () => {
    const clientSecret = { ...seed, field: "client_secret" };
    expect(providerOf(prov({ seeds: [clientSecret] }))?.seeds).toEqual([clientSecret]);
  });

  refusals("B5 passthrough", [
    ["not an array", prov({ passthrough: "x" }), [`${P}.passthrough must be an array`]],
    ["entry not an object", prov({ passthrough: [null] }), [`${P}.passthrough[0] must be an object`]],
    ["client_secret field", prov({ passthrough: [{ field: "client_secret", envVar: "X" }] }), [`${P}.passthrough[0] is malformed`]],
    ["unknown key", prov({ passthrough: [{ field: "client_id", envVar: "X", value: "v" }] }), [
      `${P}.passthrough[0].value is not a known field (known: envVar, field)`,
    ]],
  ]);
});

describe("desired network policy service entries", () => {
  const sel = (selection: unknown) => svc({}, { selection });
  refusals("B6 entry and selection", [
    ["invalid service id", svc({}, {}, "Bad_Id"), ["services.Bad_Id has an invalid service id"]],
    ["entry not an object", { version: 2, hosts: [], services: { svc: 1 } }, [`${S} must be an object`]],
    ["services is an array", { version: 2, hosts: [], services: [] }, ["services must be an object when present"]],
    ["revision 0", svc({}, { revision: 0 }), [`${S}.revision must be a positive integer`]],
    ["short digest", svc({}, { definitionDigest: "sha256:abc" }), [`${S}.definitionDigest must be a full sha256 digest`]],
    ["no resolved", { version: 2, hosts: [], services: { svc: { revision: 1, definitionDigest: digest } } }, [
      `${S}.resolved must be an object`,
    ]],
    ["unknown resolved field", svc({ extra: 1 }), [
      `${S}.resolved.extra is not a known field (known: agentEnv, hosts, oauth, parameters, requests, tokens)`,
    ]],
    ["selection not an object", sel("x"), [`${S}.selection must be an object`]],
    ["bad writeMode", sel({ writeMode: "write" }), [`${S}.selection.writeMode must be allow-write or read-only`]],
    ["skippedHosts not an array", sel({ skippedHosts: "a" }), [`${S}.selection.skippedHosts must be an array`]],
    ["skippedHost not a string", sel({ skippedHosts: [3] }), [`${S}.selection.skippedHosts[0] must be a hostname`]],
    ["skippedHost not lowercase", sel({ skippedHosts: ["B.example.com", "a.example.com"] }), [
      `${S}.selection.skippedHosts[0] must be stored as b.example.com`,
    ]],
    ["skippedHost invalid", sel({ skippedHosts: ["bad host"] }), [`${S}.selection.skippedHosts[0]: expected fully-qualified hostname`]],
    ["unknown selection key", sel({ mode: "x" }), [
      `${S}.selection.mode is not a known field (known: hostRules, skippedHosts, writeMode)`,
    ]],
    ["__proto__ service id", JSON.parse(JSON.stringify(svc({})).replace('"svc":', '"__proto__":')), [
      "services.__proto__ has an invalid service id",
    ]],
  ]);

  test("B6 the __proto__ case really carries an own __proto__ key", () => {
    const raw = JSON.parse(JSON.stringify(svc({})).replace('"svc":', '"__proto__":'));
    expect(Object.keys(raw.services)).toEqual(["__proto__"]);
  });

  test("B6 accepts a selection and sorts and de-duplicates skippedHosts", () => {
    const raw = svc({}, {
      selection: { writeMode: "allow-write", skippedHosts: ["b.example.com", "a.example.com", "b.example.com"] },
    });
    expect(validateDesiredNetworkPolicy(raw).services?.svc?.selection).toEqual({
      writeMode: "allow-write",
      skippedHosts: ["a.example.com", "b.example.com"],
    });
  });

  refusals("B7 agentEnv and parameters", [
    ["agentEnv not an array", svc({ agentEnv: "X" }), [`${S}.resolved.agentEnv must be an array`]],
    ["bad agentEnv entries", svc({ agentEnv: ["OK", "1BAD", 3] }), [
      `${S}.resolved.agentEnv[1] must be an environment variable name`,
      `${S}.resolved.agentEnv[2] must be an environment variable name`,
    ]],
    ["parameters not an array", svc({ parameters: {} }), [`${S}.resolved.parameters must be an array`]],
    ["parameter not an object", svc({ parameters: ["x"] }), [`${S}.resolved.parameters[0] must be an object`]],
    ["duplicate parameter env", svc({ agentEnv: ["A"], parameters: [param, { ...param, key: "b" }] }), [
      `${S}.resolved.parameters[1] duplicates parameter env A`,
    ]],
    ["bad oauthField", svc({ agentEnv: ["A"], parameters: [{ ...param, oauthField: "Client-Id" }] }), [
      `${S}.resolved.parameters[0] is malformed`,
    ]],
  ]);
});

describe("desired network policy top level", () => {
  refusals("B8 top level", [
    ["array policy", [], ["policy must be a JSON object"]],
    ["hosts not an array", { version: 2, hosts: "x" }, ["hosts must be an array of hostnames"]],
  ]);

  test("B8 reports every fault of one entry, in order", () => {
    const raw = {
      version: 2,
      hosts: [],
      services: {
        Bad: { revision: 0, definitionDigest: "x", resolved: { hosts: ["api.example.com"], oauth: { p: { resourceHost: 1 } } } },
      },
    };
    expect(issuesOf(raw)).toEqual([
      "services.Bad has an invalid service id",
      "services.Bad.revision must be a positive integer",
      "services.Bad.definitionDigest must be a full sha256 digest",
      "services.Bad.resolved.oauth.p.resourceHost must be a string",
    ]);
  });

  test("B9 the v3 feature scan ignores shapes it cannot read", () => {
    expect(desiredNetworkPolicyV3Features([])).toEqual([]);
    expect(desiredNetworkPolicyV3Features({
      tokens: { a: 1, b: { credentials: [1, { host: "x" }] } },
      services: { s: 1, t: { resolved: 1 } },
    })).toEqual([]);
  });
});
