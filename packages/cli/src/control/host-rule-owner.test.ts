import type { DesiredNetworkPolicyJson, DesiredServiceEntry } from "@runfree/runtime-contracts/desired-network-policy";
import type { RequestPolicyJson } from "@runfree/runtime-contracts/network-policy";
import { describe, expect, test } from "vitest";

import { CliError } from "../errors.ts";
import { hostRuleProviders, resolveHostRuleOwner, type HostRulePair } from "./host-rule-owner.ts";

const DIGEST = `sha256:${"b".repeat(64)}`;

function service(
  hosts: string[],
  requests?: Record<string, RequestPolicyJson>,
  hostRules?: Record<string, { gitPush?: "deny"; writeAction?: "allow" | "ask" | "deny" }>,
): DesiredServiceEntry {
  return {
    revision: 1,
    definitionDigest: DIGEST,
    ...(hostRules ? { selection: { hostRules } } : {}),
    resolved: { hosts, ...(requests ? { requests } : {}) },
  };
}

function layer(partial: Partial<DesiredNetworkPolicyJson> = {}): DesiredNetworkPolicyJson {
  return { version: 2, hosts: [], ...partial };
}

function pair(project: Partial<DesiredNetworkPolicyJson> = {}, local: Partial<DesiredNetworkPolicyJson> = {}): HostRulePair {
  return { project: layer(project), local: layer(local) };
}

function refusal(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(CliError);
    return (error as Error).message;
  }
  throw new Error("expected a refusal");
}

describe("resolveHostRuleOwner", () => {
  test("a host no service provides is direct when the edited layer allows it", () => {
    expect(resolveHostRuleOwner({ host: "a.example.com", scope: "project", pair: pair({ hosts: ["a.example.com"] }) }))
      .toEqual({ kind: "direct" });
  });

  test("a host no layer allows keeps today's refusal, naming host add for the edited layer", () => {
    expect(refusal(() => resolveHostRuleOwner({ host: "a.example.com", scope: "project", pair: pair() })))
      .toBe("a.example.com is not allowlisted in project policy; add it with: runfree host add a.example.com");
    expect(refusal(() => resolveHostRuleOwner({ host: "a.example.com", scope: "local", pair: pair({ hosts: ["a.example.com"] }) })))
      .toBe("a.example.com is not allowlisted in checkout-local policy; add it with: runfree host add a.example.com --local");
  });

  test("one providing service owns the rule, with or without a direct hosts entry", () => {
    const services = { github: service(["github.com"], { "github.com": { gitPush: "write" } }) };
    expect(resolveHostRuleOwner({ host: "github.com", scope: "project", pair: pair({ services }) }))
      .toEqual({ kind: "service", id: "github", layer: "project" });
    expect(resolveHostRuleOwner({ host: "github.com", scope: "project", pair: pair({ hosts: ["github.com"], services }) }))
      .toEqual({ kind: "service", id: "github", layer: "project" });
  });

  test("a local service entry replaces the project entry of the same id", () => {
    const providers = hostRuleProviders(pair(
      { services: { github: service(["github.com"]) } },
      { services: { github: service(["api.github.com"]) } },
    ), "github.com");
    expect(providers).toEqual([]);
  });

  test("a legacy direct rule beside a service rule refuses, naming the layer's --clear", () => {
    const services = { github: service(["github.com"], { "github.com": { gitPush: "write" } }) };
    const direct = { hosts: ["github.com"], requests: { "github.com": { writeAction: "allow" as const } } };
    expect(refusal(() => resolveHostRuleOwner({ host: "github.com", scope: "project", pair: pair({ ...direct, services }) })))
      .toBe("github.com has a direct rule that replaces the rule from service github; remove it with: runfree host rules github.com --clear");
    expect(refusal(() => resolveHostRuleOwner({ host: "github.com", scope: "project", pair: pair({ services }, direct) })))
      .toBe("github.com has a direct rule that replaces the rule from service github; remove it with: runfree host rules github.com --clear --local");
  });

  test("a direct rule is legacy when the service has only a hostRules setting for the host", () => {
    const services = { api: service(["api.example.com"], undefined, { "api.example.com": { gitPush: "deny" } }) };
    const direct = { hosts: ["api.example.com"], requests: { "api.example.com": { writeAction: "allow" as const } } };
    expect(refusal(() => resolveHostRuleOwner({ host: "api.example.com", scope: "project", pair: pair({ ...direct, services }) })))
      .toMatch(/has a direct rule that replaces the rule from service api/);
  });

  test("a direct rule with no competing service rule is patched as direct (R3)", () => {
    const services = { api: service(["api.example.com"]) };
    const direct = { hosts: ["api.example.com"], requests: { "api.example.com": { writeAction: "allow" as const } } };
    expect(resolveHostRuleOwner({ host: "api.example.com", scope: "project", pair: pair({ ...direct, services }) }))
      .toEqual({ kind: "direct" });
  });

  test("two providers need --service; --service must name a provider and the only rule owner", () => {
    const services = {
      alpha: service(["shared.example.com"], { "shared.example.com": { gitPush: "write" } }),
      beta: service(["shared.example.com"]),
    };
    const message = refusal(() => resolveHostRuleOwner({ host: "shared.example.com", scope: "project", pair: pair({ services }) }));
    expect(message).toContain("runfree host rules shared.example.com --service alpha");
    expect(message).toContain("runfree host rules shared.example.com --service beta");

    expect(resolveHostRuleOwner({ host: "shared.example.com", scope: "project", pair: pair({ services }), service: "alpha" }))
      .toEqual({ kind: "service", id: "alpha", layer: "project" });
    expect(refusal(() => resolveHostRuleOwner({ host: "shared.example.com", scope: "project", pair: pair({ services }), service: "beta" })))
      .toMatch(/request rule from service alpha/);
    expect(refusal(() => resolveHostRuleOwner({ host: "shared.example.com", scope: "project", pair: pair({ services }), service: "gamma" })))
      .toMatch(/service gamma does not provide shared.example.com; services that provide it: alpha, beta/);
  });

  test("--service on a host no service provides refuses", () => {
    expect(refusal(() => resolveHostRuleOwner({
      host: "a.example.com",
      scope: "project",
      pair: pair({ hosts: ["a.example.com"] }),
      service: "github",
    }))).toMatch(/service github does not provide a.example.com; no enabled service provides it/);
  });

  test("a service in the other layer refuses in both directions, naming the right form (R2)", () => {
    const projectService = pair({ services: { github: service(["github.com"]) } });
    expect(refusal(() => resolveHostRuleOwner({ host: "github.com", scope: "local", pair: projectService })))
      .toMatch(/service github, which is enabled in the project desired policy; run the command without --local, e\.g\.: runfree host rules github\.com$/);
    const localService = pair({}, { services: { github: service(["github.com"]) } });
    expect(refusal(() => resolveHostRuleOwner({ host: "github.com", scope: "project", pair: localService })))
      .toMatch(/service github, which is enabled in the checkout-local desired policy; run the command with --local, e\.g\.: runfree host rules github\.com --local$/);
    expect(resolveHostRuleOwner({ host: "github.com", scope: "local", pair: localService }))
      .toEqual({ kind: "service", id: "github", layer: "local" });
  });
});
