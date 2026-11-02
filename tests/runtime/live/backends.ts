// Live Docker backends and which live Vitest projects a command line selects.
//
// Data only: `vitest.config.ts` imports this, so it must not import vitest or
// anything that does.

/**
 * The Docker backends the live suite runs on: Docker Desktop, and native
 * Docker Engine on Linux. The label is a claim; the admission matrix checks it
 * against the daemon's own identity before any slice runs.
 */
export const LIVE_RUNTIME_BACKENDS = ["docker-desktop", "docker-engine"] as const;
export type LiveRuntimeBackend = (typeof LIVE_RUNTIME_BACKENDS)[number];

export const LIVE_RUNTIME_PROJECT = "runtime-live";

export function isLiveRuntimeBackend(value: string | undefined): value is LiveRuntimeBackend {
  return (LIVE_RUNTIME_BACKENDS as readonly (string | undefined)[]).includes(value);
}

/**
 * The backend a live run assumes when none is named. It follows the host, as
 * the Makefile's default does: docker-engine on Linux, docker-desktop
 * elsewhere. Docker Desktop on Linux names its label explicitly.
 */
export function defaultLiveRuntimeBackend(platform: NodeJS.Platform): LiveRuntimeBackend {
  return platform === "linux" ? "docker-engine" : "docker-desktop";
}

/**
 * Whether this vitest command line asks for the live project by name
 * (`--project runtime-live`) or by a live file filter
 * (`vitest run tests/runtime/live/x.live.test.ts`). Bare `vitest run` and
 * `pnpm test` select neither, so the live suite stays opt-in.
 */
export function liveRuntimeSelectedByArgv(argv: readonly string[]): boolean {
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--project" && argv[index + 1] === LIVE_RUNTIME_PROJECT) return true;
    if (arg === `--project=${LIVE_RUNTIME_PROJECT}`) return true;
    if (!arg.startsWith("-") && (arg.includes("tests/runtime/live") || arg.endsWith(".live.test.ts"))) {
      // e2e/**/*.live.test.ts belongs to cli-e2e-live, not this project.
      if (!arg.startsWith("e2e/")) return true;
    }
  }
  return false;
}

export type LiveProjectSelection = Readonly<{
  /** The label handed to live tranches: the named one, else the host default. */
  backend: string;
  /** Whether the `runtime-live` project is registered. */
  runtimeLive: boolean;
  /** Whether the packaged `cli-e2e` project is registered. */
  cliE2e: boolean;
  /** Whether the packaged `cli-e2e-live` project is registered. */
  cliE2eLive: boolean;
}>;

/**
 * Which live projects a Vitest invocation registers.
 *
 * `runtime-live` needs an accepted backend label and either a named backend
 * or a command line that selects it. `cli-e2e-live` needs the packaged
 * artifact, a Docker host, and an accepted backend label: the same labels as
 * `runtime-live`, so the packaged lane is selected on Linux whether the label
 * comes from the Makefile default (docker-engine), from
 * `scripts/run-cli-e2e.sh`'s own default, or from the host default. Any other
 * named value keeps both live projects unregistered.
 */
export function selectLiveProjects(
  env: NodeJS.ProcessEnv,
  argv: readonly string[],
  platform: NodeJS.Platform,
): LiveProjectSelection {
  const named = Boolean(env.TEST_RUNTIME_BACKEND);
  const backend = env.TEST_RUNTIME_BACKEND || defaultLiveRuntimeBackend(platform);
  const accepted = isLiveRuntimeBackend(backend);
  const cliE2e = Boolean(env.RUNFREE_E2E_ARTIFACT);
  return {
    backend,
    runtimeLive: accepted && (named || liveRuntimeSelectedByArgv(argv)),
    cliE2e,
    cliE2eLive: cliE2e && accepted && Boolean(env.RUNFREE_E2E_DOCKER_HOST),
  };
}
