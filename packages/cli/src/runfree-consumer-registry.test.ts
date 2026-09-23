import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  PROJECT_RUNFREE_CONSUMERS,
  PROJECT_RUNFREE_PATHS,
  projectRunfreeConsumer,
} from "./runfree-consumer-registry.ts";

const sourceRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(sourceRoot, "../../..");
const registrySource = fileURLToPath(new URL("./runfree-consumer-registry.ts", import.meta.url));

function productionTypeScriptFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return productionTypeScriptFiles(entryPath);
    if (!entry.isFile() || (!entry.name.endsWith(".ts") && !entry.name.endsWith(".js")) || entry.name.includes(".test.")) return [];
    if (entry.name === "embedded-assets.generated.ts") return [];
    return [entryPath];
  });
}

function projectRunfreeLiterals(source: string): string[] {
  const literals = source.matchAll(/(["'`])([^"'`\n]*\.runfree(?:\/[^"'`\s$)}\],;:]*)?)\1/g);
  const paths = new Set<string>();
  for (const match of literals) {
    const literal = match[2];
    const pathMatch = /(?:^|\/)\.runfree(?=$|\/)(?:\/[^\s,;:)}\]]*)?/.exec(literal);
    if (!pathMatch) continue;
    const normalized = pathMatch[0]
      .replace(/^\//, "")
      .replace(/[.'"`]+$/, "")
      .replace(/\/$/, "");
    paths.add(normalized);
  }
  return [...paths];
}

describe("project .runfree consumer registry", () => {
  test("has complete classification metadata and unique path ids", () => {
    expect(PROJECT_RUNFREE_CONSUMERS.map((consumer) => consumer.id).sort())
      .toEqual(Object.keys(PROJECT_RUNFREE_PATHS).sort());
    expect(new Set(PROJECT_RUNFREE_CONSUMERS.map((consumer) => consumer.id)).size)
      .toBe(PROJECT_RUNFREE_CONSUMERS.length);
    for (const consumer of PROJECT_RUNFREE_CONSUMERS) {
      expect(consumer.path).toBe(PROJECT_RUNFREE_PATHS[consumer.id]);
      expect(consumer.schema).not.toBe("");
      expect(consumer.bounds).not.toBe("");
      expect(consumer.effectiveOutput).not.toBe("");
      expect(consumer.invalidation).not.toBe("");
      expect(consumer.negativeProof).not.toBe("");
    }
  });

  test("rejects unregistered production path literals and keeps retired paths source-inert", () => {
    const found = new Map<string, string[]>();
    const productionRoots = [
      path.join(repositoryRoot, "packages/cli/src"),
      path.join(repositoryRoot, "scripts"),
      path.join(repositoryRoot, "src"),
      path.join(repositoryRoot, "bin"),
    ];
    for (const filePath of productionRoots.flatMap(productionTypeScriptFiles)) {
      if (filePath === registrySource) continue;
      for (const candidate of projectRunfreeLiterals(fs.readFileSync(filePath, "utf8"))) {
        const files = found.get(candidate) ?? [];
        files.push(path.relative(repositoryRoot, filePath));
        found.set(candidate, files);
      }
    }

    const unregistered = [...found].filter(([candidate]) => projectRunfreeConsumer(candidate) === undefined);
    expect(unregistered, "new .runfree path literals must be classified in runfree-consumer-registry.ts").toEqual([]);

    const retired = PROJECT_RUNFREE_CONSUMERS.filter((consumer) => consumer.consumption === "inert");
    const consumedRetired = retired.flatMap((consumer) =>
      [...found].filter(([candidate]) => candidate === consumer.path || candidate.startsWith(`${consumer.path}/`)));
    expect(consumedRetired, "retired .runfree paths must not appear in production consumers").toEqual([]);
  });

  test("unknown paths are inert rather than inherited from the root entry", () => {
    expect(projectRunfreeConsumer(".runfree/plugins/attacker.ts")).toBeUndefined();
    expect(projectRunfreeConsumer(".runfree/approved-network.json")).toBeUndefined();
    expect(projectRunfreeConsumer(".runfree/state/runtime.json")?.consumption).toBe("inert");
    expect(projectRunfreeConsumer(".runfree/image/scripts/install.sh")?.id).toBe("image");
  });
});
