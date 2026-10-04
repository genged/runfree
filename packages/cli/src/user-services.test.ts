import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { readAndValidateUserServiceFile } from "./user-services.ts";

function writeDefinition(dir: string, id: string, definition: Record<string, unknown>): string {
  const filePath = path.join(dir, `${id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(definition));
  return filePath;
}

describe("user service definitions (SR4/A1 reserved suffix)", () => {
  let dir: string;

  function makeDir(): string {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-user-service-def-"));
    return dir;
  }

  function cleanup(): void {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  test("refuses a host using the reserved runfree.internal suffix", () => {
    makeDir();
    try {
      const filePath = writeDefinition(dir, "user-acme", {
        schemaVersion: 1,
        id: "user-acme",
        label: "Acme",
        revision: 1,
        hosts: [{ host: "x.runfree.internal" }],
        explanations: ["user-defined test service"],
      });
      expect(() => readAndValidateUserServiceFile(filePath)).toThrow("reserved runfree.internal suffix");
    } finally {
      cleanup();
    }
  });

  test("refuses a credential destination using the reserved runfree.internal suffix", () => {
    makeDir();
    try {
      const filePath = writeDefinition(dir, "user-acme", {
        schemaVersion: 1,
        id: "user-acme",
        label: "Acme",
        revision: 1,
        hosts: [{ host: "api.acme.test" }],
        explanations: ["user-defined test service"],
        credential: {
          tokenDescription: "Acme API token",
          agentEnv: ["ACME_TOKEN"],
          credentials: [{ host: "x.runfree.internal", header: "Authorization", scheme: "bearer" }],
        },
      });
      expect(() => readAndValidateUserServiceFile(filePath)).toThrow("reserved runfree.internal suffix");
    } finally {
      cleanup();
    }
  });
});
