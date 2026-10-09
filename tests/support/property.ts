// Shared fast-check parameters for the `*.property.test.ts` files.
//
// Every run uses a fresh random seed unless `RUNFREE_PROP_SEED` names one. A
// failure is a finding, not a flake: fast-check prints the seed, the shrink
// path, and the shrunk counterexample, and the replay command is
//
//   RUNFREE_PROP_SEED=<seed> RUNFREE_PROP_PATH=<path> pnpm exec vitest run <file> -t "<property name>"
//
// Classify the failure (product, test/oracle, infrastructure) before rerunning
// anything, and keep the counterexample as a plain example test beside the
// property.

import type { Parameters } from "fast-check";

export const PROPERTY_RUNS_ENV = "RUNFREE_PROP_RUNS";
export const PROPERTY_SEED_ENV = "RUNFREE_PROP_SEED";
export const PROPERTY_PATH_ENV = "RUNFREE_PROP_PATH";

const DEFAULT_PROPERTY_RUNS = 200;

/**
 * `fc.assert` parameters from the environment, with per-property overrides.
 *
 * Malformed values are refused rather than defaulted: `RUNFREE_PROP_RUNS=1e5`
 * silently falling back to 200 would make a soak campaign look like it ran.
 * An override's `numRuns` is the property's default; `RUNFREE_PROP_RUNS`
 * still wins over it, so a soak run reaches every property.
 */
export function propertyParameters<T = unknown>(
  overrides: Parameters<T> = {},
  env: NodeJS.ProcessEnv = process.env,
): Parameters<T> {
  const parameters: Parameters<T> = { verbose: 1, ...overrides };
  const runs = readPositiveInteger(env, PROPERTY_RUNS_ENV);
  parameters.numRuns = runs ?? overrides.numRuns ?? DEFAULT_PROPERTY_RUNS;
  const seed = readSeed(env);
  if (seed !== undefined) parameters.seed = seed;
  const replayPath = readNonEmpty(env, PROPERTY_PATH_ENV);
  if (replayPath !== undefined) {
    if (seed === undefined) {
      throw new Error(`${PROPERTY_PATH_ENV} replays a shrunk case and needs ${PROPERTY_SEED_ENV}`);
    }
    if (!/^[0-9]+(?::[0-9]+)*$/u.test(replayPath)) {
      throw new Error(`${PROPERTY_PATH_ENV} must be a fast-check path like 12:0:3, got ${JSON.stringify(replayPath)}`);
    }
    parameters.path = replayPath;
  }
  return parameters;
}

function readNonEmpty(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name];
  return value === undefined || value === "" ? undefined : value;
}

function readPositiveInteger(env: NodeJS.ProcessEnv, name: string): number | undefined {
  const value = readNonEmpty(env, name);
  if (value === undefined) return undefined;
  if (!/^[1-9][0-9]*$/u.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new Error(`${name} must be a positive integer, got ${JSON.stringify(value)}`);
  }
  return Number(value);
}

function readSeed(env: NodeJS.ProcessEnv): number | undefined {
  const value = readNonEmpty(env, PROPERTY_SEED_ENV);
  if (value === undefined) return undefined;
  // fast-check prints seeds as signed 32-bit integers.
  const seed = Number(value);
  if (!/^-?[0-9]+$/u.test(value) || !Number.isSafeInteger(seed) || seed < -(2 ** 31) || seed >= 2 ** 32) {
    throw new Error(`${PROPERTY_SEED_ENV} must be the integer seed fast-check printed, got ${JSON.stringify(value)}`);
  }
  return seed;
}
