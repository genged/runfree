import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { formatDesiredPolicyFile, readBoundedProjectJson } from "./project-json.ts";

describe("bounded project JSON reader", () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-project-json-"));
    fs.mkdirSync(path.join(root, ".runfree"));
  });
  afterEach(() => fs.rmSync(root, { recursive: true }));

  test("reads a regular recognized file", () => {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    expect(readBoundedProjectJson(root, ".runfree/network-policy.json")?.parsed).toEqual({ version: 2, hosts: [] });
  });

  test("rejects duplicates, oversize input, links, and unrecognized paths", () => {
    const policy = path.join(root, ".runfree", "network-policy.json");
    fs.writeFileSync(policy, `{"version":2,"version":2,"hosts":[]}`);
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json")).toThrow("duplicate object key");

    fs.writeFileSync(policy, "x".repeat(65));
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json", { maxBytes: 64 })).toThrow("64-byte limit");

    fs.unlinkSync(policy);
    fs.symlinkSync("../outside.json", policy);
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json")).toThrow("regular, non-hard-linked");
    expect(() => readBoundedProjectJson(root, ".runfree/generated.json")).toThrow("unrecognized");
    expect(() => readBoundedProjectJson(root, ".runfree/generated/policy.json")).toThrow("unrecognized");
  });

  test("rejects a symlinked control root before opening a child", () => {
    fs.rmSync(path.join(root, ".runfree"), { recursive: true });
    fs.symlinkSync(os.tmpdir(), path.join(root, ".runfree"));
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json")).toThrow("normal directory");
  });

  test("represents an absent optional file without parsing another path", () => {
    expect(readBoundedProjectJson(root, ".runfree/network-policy.local.json", { allowMissing: true })).toBeUndefined();
  });
});

describe("desired-policy file format", () => {
  const policy: DesiredNetworkPolicyJson = {
    version: 2,
    hosts: ["files.example.com", "api.example.com"],
    writeApproval: "deny",
    tokens: {
      "example-api": {
        description: "Example API token",
        credentials: [
          { host: "files.example.com", header: "X-Api-Key", scheme: "raw" },
          { host: "api.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/v1" },
        ],
      },
    },
    requests: { "api.example.com": { pathPrefixes: ["/v1"], methods: ["POST", "GET"] } },
  };

  // Reverses object key order at every depth; arrays keep their order.
  function reverseKeys(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(reverseKeys);
    if (value === null || typeof value !== "object") return value;
    return Object.fromEntries(Object.entries(value).reverse().map(([key, entry]) => [key, reverseKeys(entry)]));
  }

  test("keeps the policy identity and puts top-level fields in schema order", () => {
    const file = formatDesiredPolicyFile(policy);
    expect(canonicalDesiredNetworkPolicy(JSON.parse(file) as DesiredNetworkPolicyJson))
      .toBe(canonicalDesiredNetworkPolicy(policy));
    expect(Object.keys(JSON.parse(file) as object)).toEqual(["version", "hosts", "requests", "tokens", "writeApproval"]);
    expect(file.split("\n").length).toBeGreaterThan(10);
    expect(file.endsWith("}\n")).toBe(true);
  });

  test("equal policies give equal files whatever the input key order", () => {
    expect(formatDesiredPolicyFile(reverseKeys(policy) as DesiredNetworkPolicyJson)).toBe(formatDesiredPolicyFile(policy));
  });

  test("the init template is already in the written format", () => {
    const templatePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../templates/network-policy.json");
    const template = fs.readFileSync(templatePath, "utf8");
    expect(formatDesiredPolicyFile(JSON.parse(template) as DesiredNetworkPolicyJson)).toBe(template);
  });
});
