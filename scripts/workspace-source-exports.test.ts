// Tests and the root typecheck must read workspace package sources. A package
// export into `dist/`, or a root project reference, makes them read whatever
// `pnpm build:runtime` produced last, so an edited source goes untested.

import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

import { expect, test } from "vitest";

import { repoRoot } from "../tests/support/prebuilt-entry.ts";

type ExportTarget = string | { readonly [condition: string]: ExportTarget };

function exportTargets(value: ExportTarget): string[] {
  return typeof value === "string" ? [value] : Object.values(value).flatMap(exportTargets);
}

test("every workspace package export targets an existing file under src/", () => {
  const packagesDir = path.join(repoRoot, "packages");
  const offenders: string[] = [];
  for (const entry of fs.readdirSync(packagesDir, { withFileTypes: true })) {
    const manifestPath = path.join(packagesDir, entry.name, "package.json");
    if (!entry.isDirectory() || !fs.existsSync(manifestPath)) continue;
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
      name: string;
      exports?: Record<string, ExportTarget>;
    };
    for (const [subpath, value] of Object.entries(manifest.exports ?? {})) {
      for (const target of exportTargets(value)) {
        const onDisk = path.join(packagesDir, entry.name, target);
        if (!target.startsWith("./src/") || !fs.existsSync(onDisk)) {
          offenders.push(`${manifest.name} ${subpath} -> ${target}`);
        }
      }
    }
  }
  expect(offenders).toEqual([]);
});

test("the proxy resolves runtime-contracts to its source", () => {
  const requireFromProxy = createRequire(path.join(repoRoot, "packages", "proxy", "package.json"));
  const resolved = fs.realpathSync(requireFromProxy.resolve("@runfree/runtime-contracts/network-policy"));
  expect(resolved).toBe(
    fs.realpathSync(path.join(repoRoot, "packages", "runtime-contracts", "src", "network-policy.ts")),
  );
});

test("the root typecheck has no project references", () => {
  // With references, `tsc --noEmit` substitutes each referenced package's
  // `dist/*.d.ts` for its sources. Package tsconfigs keep theirs for `tsc -b`.
  const tsconfig = JSON.parse(fs.readFileSync(path.join(repoRoot, "tsconfig.json"), "utf8")) as {
    references?: unknown;
  };
  expect(tsconfig.references).toBeUndefined();
});
