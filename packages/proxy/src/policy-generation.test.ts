import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import { expect, test } from "vitest";

import { loadProxyPolicy, validateProxyPolicy } from "./policy.ts";

const policy = {
  hosts: ["api.github.com"],
  tokens: {
    github: {
      description: "GitHub API",
      credentials: [
        { host: "api.github.com", header: "Authorization", scheme: "bearer" },
      ],
    },
  },
};

test("proxy validation uses runtime-contracts generation", () => {
  expect(validateProxyPolicy(policy).generation).toBe(validateNetworkPolicy(policy).generation);
});

test("loadProxyPolicy returns the shared generation from a file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-policy-generation-"));
  const file = path.join(dir, "network-policy.json");
  fs.writeFileSync(file, `${JSON.stringify(policy, null, 2)}\n`);

  expect(loadProxyPolicy(file).generation).toBe(validateNetworkPolicy(policy).generation);
});
