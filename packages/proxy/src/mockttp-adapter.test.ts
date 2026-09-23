import fs from "node:fs";
import path from "node:path";
import { beforeAll, describe, expect, test } from "vitest";

import {
  generateProxyCA,
  runMockttpAdapterSelfTest,
  type MockttpAdapterSelfTestMutations,
} from "./mockttp-adapter.ts";

let ca: { cert: string; key: string };

beforeAll(async () => {
  ca = await generateProxyCA();
});

describe("mockttp adapter boot contract", () => {
  test("is the sole source module that imports mockttp or its internals", () => {
    const sourceDir = path.resolve("packages/proxy/src");
    const offenders = fs.readdirSync(sourceDir)
      .filter((name) => name.endsWith(".ts") && name !== "mockttp-adapter.ts")
      .filter((name) => {
        const source = fs.readFileSync(path.join(sourceDir, name), "utf8");
        return /(?:from\s+["']mockttp|require\(["']mockttp)/.test(source);
      });
    expect(offenders).toEqual([]);
  });

  test("passes against the pinned dependency's live TLS and request behavior", async () => {
    await expect(runMockttpAdapterSelfTest(ca)).resolves.toBeUndefined();
  });

  const mutations: Array<{ label: string; mutate: MockttpAdapterSelfTestMutations; message: RegExp }> = [
    {
      label: "remote-port propagation",
      mutate: { remotePort: (port) => (port ?? 0) + 1 },
      message: /remotePort propagation failed/,
    },
    {
      label: "tunnel destination propagation",
      mutate: { destinationHost: () => "mutated.invalid" },
      message: /tunnel destination propagation failed/,
    },
    {
      label: "socket metadata seal target",
      mutate: { sealTargetExists: () => false },
      message: /socket metadata seal failed/,
    },
    {
      label: "single-name leaf certificate",
      mutate: { leafSubjectAltName: (value) => `${value}, DNS:mutated.invalid` },
      message: /leaf SAN contract failed/,
    },
    {
      label: "private connection serial mapping",
      mutate: { trustedSerial: (serial) => (serial ?? 0) + 1 },
      message: /trusted socket admission serial did not survive/,
    },
  ];

  for (const mutation of mutations) {
    test(`aborts startup when ${mutation.label} changes`, async () => {
      await expect(runMockttpAdapterSelfTest({ ...ca, mutations: mutation.mutate }))
        .rejects.toThrow(mutation.message);
    });
  }
});
