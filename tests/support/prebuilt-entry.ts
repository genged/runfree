// Prebuilt subprocess entrypoints for the unit-test spawn harnesses.
//
// Test files spawn the CLI and the proxy server as real subprocesses. Spawning
// them through `node --import tsx <entry>.ts` costs ~1.5s per invocation
// (process boot plus transpiling and loading the full module graph), and the
// suite makes hundreds of such spawns. `tests/support/build-test-bundles.ts`
// (the Vitest globalSetup) bundles each entrypoint once per run with Bun — the
// same bundler that compiles the shipped binary — and the harnesses spawn the
// bundle under plain Node in ~0.2s instead.
//
// When a bundle is absent (Bun not installed, or the globalSetup did not run),
// the argv helpers fall back to the tsx invocation the harnesses always used,
// so the suite works everywhere and is merely slower without Bun. The
// globalSetup deletes the bundles when Bun is unavailable, so a stale bundle
// from an earlier run can never shadow current sources.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export const CLI_ENTRY_SOURCE = path.join(repoRoot, "src", "cli.ts");
export const PROXY_SERVER_ENTRY_SOURCE = path.join(repoRoot, "packages", "proxy", "src", "server.ts");

// The CLI bundle must sit exactly four directories below the repo root:
// `admin/context.ts` falls back to resolving the package root four directories
// above the executing module (its depth under `packages/cli/src/admin/`), and
// after bundling the executing module is the bundle itself.
export const CLI_BUNDLE_PATH = path.join(repoRoot, "node_modules", ".cache", "runfree-tests", "cli", "cli.mjs");

// The proxy bundle must live under `packages/proxy/`: `mockttp-adapter.ts`
// loads pinned mockttp internals through `createRequire(import.meta.url)`,
// which Bun leaves as runtime requires, so bare specifiers resolve relative to
// the bundle location and must reach `packages/proxy/node_modules`.
export const PROXY_SERVER_BUNDLE_PATH = path.join(
  repoRoot,
  "packages",
  "proxy",
  "node_modules",
  ".cache",
  "runfree-tests",
  "server.mjs",
);

// The live session-admission runners (`tests/runtime/session-admission-*.ts`)
// import the CLI's runtime modules and so inherit the same depth constraint;
// they sit beside the CLI bundle.
export const SESSION_ADMISSION_CRASH_ENTRY_SOURCE = path.join(repoRoot, "tests", "runtime", "session-admission-crash.ts");
export const SESSION_ADMISSION_MATRIX_ENTRY_SOURCE = path.join(repoRoot, "tests", "runtime", "session-admission-matrix.ts");
export const SESSION_ADMISSION_CRASH_BUNDLE_PATH = path.join(path.dirname(CLI_BUNDLE_PATH), "session-admission-crash.mjs");
export const SESSION_ADMISSION_MATRIX_BUNDLE_PATH = path.join(path.dirname(CLI_BUNDLE_PATH), "session-admission-matrix.mjs");

function entryArgv(bundlePath: string, sourcePath: string): readonly string[] {
  return fs.existsSync(bundlePath)
    ? ["--enable-source-maps", bundlePath]
    : ["--import", "tsx", sourcePath];
}

/** Node argv (before CLI arguments) that runs the CLI under test. */
export function cliEntryArgv(): readonly string[] {
  return entryArgv(CLI_BUNDLE_PATH, CLI_ENTRY_SOURCE);
}

/** Node argv (before server arguments) that runs the proxy server under test. */
export function proxyServerEntryArgv(): readonly string[] {
  return entryArgv(PROXY_SERVER_BUNDLE_PATH, PROXY_SERVER_ENTRY_SOURCE);
}

/** Node argv (before runner arguments) that runs the live crash/launch runner. */
export function sessionAdmissionCrashEntryArgv(): readonly string[] {
  return entryArgv(SESSION_ADMISSION_CRASH_BUNDLE_PATH, SESSION_ADMISSION_CRASH_ENTRY_SOURCE);
}

/** Node argv (before runner arguments) that runs the live nominal admission matrix. */
export function sessionAdmissionMatrixEntryArgv(): readonly string[] {
  return entryArgv(SESSION_ADMISSION_MATRIX_BUNDLE_PATH, SESSION_ADMISSION_MATRIX_ENTRY_SOURCE);
}
