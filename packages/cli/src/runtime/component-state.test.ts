import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { forEachCrashPoint } from "../../../../tests/support/crash-steps.ts";

import {
  createRuntimeComponentState,
  readEffectiveRuntimeGeneration,
  readRuntimeGenerationManifest,
  runtimeEffectiveSelectionPath,
  runtimeGenerationDigest,
  runtimeGenerationManifestPath,
  runtimeMaterializationDigest,
  runtimeMaterializationRoot,
  selectEffectiveRuntimeGeneration,
  serializeRuntimeGenerationManifest,
  sha256Digest,
  type RuntimeGenerationManifest,
} from "./component-state.ts";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function digest(label: string): string {
  return sha256Digest(label);
}

function manifest(projectId = "project-a"): RuntimeGenerationManifest {
  const components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: digest("embedded-agent"),
    selectedAgentImageInputDigest: digest("selected-agent"),
    selectedAgentImageKind: "project",
    proxyImageInputDigest: digest("proxy"),
    topologyDigest: digest(`topology-${projectId}`),
    hostHelperDigest: digest("helpers"),
  });
  return {
    schemaVersion: 1,
    projectId,
    composeProject: `runfree-${projectId}`,
    components,
    images: {
      agent: "runfree/agent-project:sha256-selected",
      proxy: "runfree/proxy-runtime:sha256-proxy",
    },
    renderedComposeSha256: digest("compose"),
  };
}

function publish(stateDir: string, value: RuntimeGenerationManifest): void {
  const root = runtimeMaterializationRoot(stateDir, value.components.materializationDigest);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    runtimeGenerationManifestPath(stateDir, value.components.materializationDigest),
    serializeRuntimeGenerationManifest(value),
    { mode: 0o600 },
  );
}

describe("runtime component state", () => {
  test("uses only runtime-container components for the runtime generation", () => {
    const first = manifest();
    const helperOnly = createRuntimeComponentState({
      ...first.components,
      hostHelperDigest: digest("changed-helpers"),
    });

    expect(helperOnly.runtimeGenerationDigest).toBe(first.components.runtimeGenerationDigest);
    expect(helperOnly.materializationDigest).not.toBe(first.components.materializationDigest);
  });

  test("changes the runtime generation for each lifecycle component", () => {
    const first = manifest().components;
    for (const changed of ["selectedAgentImageInputDigest", "proxyImageInputDigest", "topologyDigest"] as const) {
      const candidate = createRuntimeComponentState({
        ...first,
        [changed]: digest(`changed-${changed}`),
      });
      expect(candidate.runtimeGenerationDigest, changed).not.toBe(first.runtimeGenerationDigest);
    }
  });

  test("rejects malformed component inputs", () => {
    expect(() => runtimeGenerationDigest({
      digestSchemaVersion: 1,
      selectedAgentImageInputDigest: "short",
      proxyImageInputDigest: digest("proxy"),
      topologyDigest: digest("topology"),
    })).toThrow("full sha256 digest");
    expect(() => runtimeMaterializationDigest({
      digestSchemaVersion: 1,
      runtimeGenerationDigest: digest("runtime"),
      hostHelperDigest: "sha256:nope",
    })).toThrow("full sha256 digest");
  });
});

describe("runtime generation selection", () => {
  test("selects one immutable materialization through an atomic pointer", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-components-"));
    roots.push(stateDir);
    const first = manifest("first");
    const second = manifest("second");
    publish(stateDir, first);
    publish(stateDir, second);

    selectEffectiveRuntimeGeneration(stateDir, first.components.materializationDigest);
    expect(readEffectiveRuntimeGeneration(stateDir)).toEqual(first);
    selectEffectiveRuntimeGeneration(stateDir, second.components.materializationDigest);
    expect(readEffectiveRuntimeGeneration(stateDir)).toEqual(second);
    expect(fs.statSync(runtimeEffectiveSelectionPath(stateDir)).mode & 0o777).toBe(0o600);
  });

  test("no crash point of a selection leaves a pointer that reads as malformed", () => {
    // The pointer is published by temp file, fsync, rename, directory fsync.
    // Crashed after any of those writes, a reader sees the previous
    // selection, no selection, or the new one — never a torn file that would
    // wedge every later command on "runtime effective selection is malformed".
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-components-"));
    roots.push(stateDir);
    const first = manifest("first");
    const second = manifest("second");
    publish(stateDir, first);
    publish(stateDir, second);
    const points = forEachCrashPoint({
      root: stateDir,
      prepare: () => selectEffectiveRuntimeGeneration(stateDir, first.components.materializationDigest),
      run: () => selectEffectiveRuntimeGeneration(stateDir, second.components.materializationDigest),
      inspect: (point, outcome) => {
        expect(outcome.kind, `crash point ${point}`).toBe("crashed");
        const selected = readEffectiveRuntimeGeneration(stateDir);
        expect([first, second], `crash point ${point}`).toContainEqual(selected);
        // Nothing but the pointer may remain beside it: no stranded temp file.
        expect(fs.readdirSync(path.dirname(runtimeEffectiveSelectionPath(stateDir))).filter((entry) => entry.endsWith(".tmp")))
          .toEqual([]);
      },
    });
    // One publishing write: the rename. (The temp file is written through a
    // descriptor and removed only on failure.)
    expect(points).toBe(1);
  });

  test("an unreadable pointer names the command that clears it", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-components-"));
    roots.push(stateDir);
    fs.mkdirSync(path.dirname(runtimeEffectiveSelectionPath(stateDir)), { recursive: true });
    fs.writeFileSync(runtimeEffectiveSelectionPath(stateDir), "{ torn");
    expect(() => readEffectiveRuntimeGeneration(stateDir)).toThrow("runtime effective selection is malformed; recreate the runtime with `runfree destroy --force`, then `runfree up`");
    fs.writeFileSync(runtimeEffectiveSelectionPath(stateDir), JSON.stringify({ schemaVersion: 1, materializationDigest: digest("gone") }));
    expect(() => readEffectiveRuntimeGeneration(stateDir)).toThrow("references a missing materialization; recreate the runtime with `runfree destroy --force`");
  });

  test("rejects a manifest whose directory identity contradicts its contents", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-components-"));
    roots.push(stateDir);
    const value = manifest();
    publish(stateDir, value);
    const wrongDigest = digest("wrong");
    const wrongRoot = runtimeMaterializationRoot(stateDir, wrongDigest);
    fs.mkdirSync(wrongRoot, { recursive: true });
    fs.copyFileSync(
      runtimeGenerationManifestPath(stateDir, value.components.materializationDigest),
      runtimeGenerationManifestPath(stateDir, wrongDigest),
    );

    expect(() => readRuntimeGenerationManifest(stateDir, wrongDigest)).toThrow("manifest is invalid");
  });

  test("rejects symlinked selection state and missing targets", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-components-"));
    roots.push(stateDir);
    fs.mkdirSync(path.dirname(runtimeEffectiveSelectionPath(stateDir)), { recursive: true });
    fs.symlinkSync("missing.json", runtimeEffectiveSelectionPath(stateDir));
    expect(() => readEffectiveRuntimeGeneration(stateDir)).toThrow("not a normal file");
    fs.unlinkSync(runtimeEffectiveSelectionPath(stateDir));
    expect(() => selectEffectiveRuntimeGeneration(stateDir, digest("missing"))).toThrow("missing runtime materialization");
  });

  test("fails closed on unknown fields and digest tampering", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-components-"));
    roots.push(stateDir);
    const value = manifest();
    publish(stateDir, value);
    const manifestPath = runtimeGenerationManifestPath(stateDir, value.components.materializationDigest);
    fs.writeFileSync(manifestPath, JSON.stringify({ ...value, unexpected: true }));
    expect(() => readRuntimeGenerationManifest(stateDir, value.components.materializationDigest)).toThrow("manifest is invalid");
  });
});
