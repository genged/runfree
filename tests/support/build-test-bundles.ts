// Vitest globalSetup: prebuild the subprocess entrypoints the spawn harnesses
// run, once per Vitest invocation. See `tests/support/prebuilt-entry.ts` for
// why, and for the constraints on where each bundle lives.
//
// Bun is the same bundler `pnpm build:bin` compiles the shipped binary with, so
// the bundles exercise the release compilation path more closely than tsx did.
// Without Bun on PATH this deletes any leftover bundles and returns: the
// harnesses fall back to tsx spawns, and correctness does not depend on Bun.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import type { TestProject } from "vitest/node";

import {
  CLI_BUNDLE_PATH,
  PROXY_SERVER_BUNDLE_PATH,
  repoRoot,
  SESSION_ADMISSION_CRASH_BUNDLE_PATH,
  SESSION_ADMISSION_CRASH_ENTRY_SOURCE,
  SESSION_ADMISSION_MATRIX_BUNDLE_PATH,
  SESSION_ADMISSION_MATRIX_ENTRY_SOURCE,
} from "./prebuilt-entry.ts";

// The bundle entry is the real CLI module, not the `src/cli.ts` delegate,
// mirroring `scripts/build-bin.ts`.
const CLI_BUNDLE_ENTRY = path.join(repoRoot, "packages", "cli", "src", "cli.ts");
const PROXY_SERVER_BUNDLE_ENTRY = path.join(repoRoot, "packages", "proxy", "src", "server.ts");

export type BundleSpec = Readonly<{ entry: string; outfile: string; external: readonly string[] }>;

// Fully bundled, mirroring the shipped binary. Workspace package exports
// point at TypeScript sources, so the CLI's dependencies cannot be
// externalized anyway.
const CLI_BUNDLE: BundleSpec = { entry: CLI_BUNDLE_ENTRY, outfile: CLI_BUNDLE_PATH, external: [] };

/**
 * A package's third-party dependencies, as `bun build --external` patterns.
 *
 * Workspace dependencies are left out, so they are bundled: their exports
 * point at TypeScript sources that plain Node cannot load (NodeNext `.js`
 * specifiers name files that exist only as `.ts`).
 */
function thirdPartyExternals(packageDir: string): readonly string[] {
  const manifest = JSON.parse(fs.readFileSync(path.join(packageDir, "package.json"), "utf8")) as {
    dependencies?: Record<string, string>;
  };
  return Object.entries(manifest.dependencies ?? {})
    .filter(([, version]) => !version.startsWith("workspace:"))
    .flatMap(([name]) => [name, `${name}/*`]);
}

/** What the ordinary (non-Docker) suite spawns. */
export const UNIT_BUNDLES: readonly BundleSpec[] = [
  CLI_BUNDLE,
  // Third-party dependencies stay external: `mockttp-adapter.ts` pins mockttp
  // internals through `createRequire`, and a bundled second mockttp instance
  // would not share the trusted-socket metadata of the one loaded from disk
  // (the server startup self-test catches exactly that). External resolution
  // from the bundle's location reaches `packages/proxy/node_modules`, matching
  // how the tsx-run server resolved the same modules.
  {
    entry: PROXY_SERVER_BUNDLE_ENTRY,
    outfile: PROXY_SERVER_BUNDLE_PATH,
    external: thirdPartyExternals(path.join(repoRoot, "packages", "proxy")),
  },
];

/**
 * What the live runtime tranches spawn: the CLI (every `fixture.runfree` call)
 * and the two session-admission runners each tranche invokes per case. A live
 * run makes well over a hundred such spawns, so the ~1.5s tsx boot per spawn
 * was minutes of pure interpreter startup per `make test-runtime`.
 */
export const LIVE_BUNDLES: readonly BundleSpec[] = [
  CLI_BUNDLE,
  { entry: SESSION_ADMISSION_CRASH_ENTRY_SOURCE, outfile: SESSION_ADMISSION_CRASH_BUNDLE_PATH, external: [] },
  { entry: SESSION_ADMISSION_MATRIX_ENTRY_SOURCE, outfile: SESSION_ADMISSION_MATRIX_BUNDLE_PATH, external: [] },
];

function bunAvailable(): boolean {
  const probe = childProcess.spawnSync("bun", ["--version"], { stdio: "ignore" });
  return !probe.error && probe.status === 0;
}

function buildBundle(entry: string, outfile: string, external: readonly string[]): void {
  fs.mkdirSync(path.dirname(outfile), { recursive: true });
  // Build to a temporary name and rename into place: a concurrently running
  // Vitest invocation spawning the bundle must see the previous complete file
  // or the new one, never a partial write.
  const staging = `${outfile}.building-${process.pid}`;
  const result = childProcess.spawnSync(
    "bun",
    [
      "build",
      entry,
      "--target=node",
      "--packages=bundle",
      ...external.map((pattern) => `--external=${pattern}`),
      "--sourcemap=inline",
      `--outfile=${staging}`,
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (result.error || result.status !== 0) {
    fs.rmSync(staging, { force: true });
    // Bun is present but cannot bundle the entry. Fail the run instead of
    // silently falling back: the release binary is built the same way, so this
    // is a real breakage worth surfacing here.
    throw new Error(
      `test bundle build failed for ${path.relative(repoRoot, entry)}:\n${result.stderr ?? String(result.error)}`,
    );
  }
  fs.renameSync(staging, outfile);
}

function buildAll(bundles: readonly BundleSpec[]): void {
  if (!bunAvailable()) {
    // Never leave a stale bundle behind for the harnesses to prefer over
    // current sources.
    for (const { outfile } of bundles) fs.rmSync(outfile, { force: true });
    process.stderr.write(
      "test bundles: bun not found on PATH; subprocess tests will spawn through tsx (slower)\n",
    );
    return;
  }
  for (const { entry, outfile, external } of bundles) buildBundle(entry, outfile, external);
}

const builtThisInvocation = new Set<string>();

/**
 * A globalSetup that builds one bundle list once per Vitest invocation.
 *
 * More than one project may declare the same setup (the bundles are built
 * once, not once per project), and the unit and live setups share the CLI
 * bundle: a second setup in the same invocation rebuilds only what its own
 * list adds.
 */
export function createBundleSetup(bundles: readonly BundleSpec[]): (project: TestProject) => void {
  return (project: TestProject): void => {
    buildOnce(bundles);
    // Watch mode: sources change between reruns, so rebuild before each one.
    project.onTestsRerun(async () => {
      for (const { outfile } of bundles) builtThisInvocation.delete(outfile);
      buildOnce(bundles);
    });
  };
}

function buildOnce(bundles: readonly BundleSpec[]): void {
  const pending = bundles.filter(({ outfile }) => !builtThisInvocation.has(outfile));
  if (pending.length === 0) return;
  buildAll(pending);
  for (const { outfile } of pending) builtThisInvocation.add(outfile);
}

export default createBundleSetup(UNIT_BUNDLES);
