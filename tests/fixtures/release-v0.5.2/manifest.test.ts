import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { desiredNetworkPolicyDigest as releasedDesiredNetworkPolicyDigest } from "./runtime-contracts/desired-network-policy.ts";
import { validateNetworkPolicy as releasedValidateNetworkPolicy } from "./runtime-contracts/network-policy.ts";

// The v0.5.2 policy readers, frozen byte for byte. Later changes to the policy
// contracts prove compatibility against these: an older proxy or CLI must
// refuse what it cannot honor rather than silently drop it. The manifest pins
// each file to the git blob id of its source at the release tag, so an edit to
// a fixture (including a formatter run) fails here instead of quietly turning
// the "old reader" into a new one.

const fixtureRoot = path.dirname(fileURLToPath(import.meta.url));

type Manifest = {
  commit: string;
  files: Record<string, { blob: string; source: string }>;
  tag: string;
};

function gitBlobId(bytes: Buffer): string {
  return crypto.createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes])).digest("hex");
}

const manifest = JSON.parse(fs.readFileSync(path.join(fixtureRoot, "MANIFEST.json"), "utf8")) as Manifest;

describe("release v0.5.2 fixture manifest", () => {
  test("names the release and every fixture module", () => {
    expect(manifest.tag).toBe("v0.5.2");
    expect(manifest.commit).toMatch(/^[0-9a-f]{40}$/);
    const onDisk = fs.readdirSync(path.join(fixtureRoot, "runtime-contracts")).map((name) => `runtime-contracts/${name}`).sort();
    expect(Object.keys(manifest.files).sort()).toEqual(onDisk);
  });

  test.each(Object.entries(manifest.files))("%s matches its release blob", (relative, entry) => {
    const bytes = fs.readFileSync(path.join(fixtureRoot, relative));
    expect(gitBlobId(bytes)).toBe(entry.blob);
    expect(entry.source).toBe(`packages/runtime-contracts/src/${path.basename(relative)}`);
  });

  test("imports only each other and node built-ins", () => {
    for (const relative of Object.keys(manifest.files)) {
      const source = fs.readFileSync(path.join(fixtureRoot, relative), "utf8");
      for (const match of source.matchAll(/from\s+"([^"]+)"/gu)) {
        const specifier = match[1];
        if (specifier.startsWith("node:")) continue;
        expect(specifier, `${relative} imports ${specifier}`).toMatch(/^\.\/[a-z-]+\.js$/u);
        expect(manifest.files[`runtime-contracts/${specifier.slice(2, -3)}.ts`], `${relative} imports ${specifier}`).toBeDefined();
      }
    }
  });

  test("the released readers load and run", () => {
    const loaded = releasedValidateNetworkPolicy({ hosts: ["example.com"] });
    expect(loaded.allowedHosts).toEqual(["example.com"]);
    expect(loaded.generation).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(releasedDesiredNetworkPolicyDigest({ version: 2, hosts: [] })).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });
});
