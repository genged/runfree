import fs from "node:fs";
import path from "node:path";

export const E2E_ARTIFACT_ENV = "RUNFREE_E2E_ARTIFACT";

const SOURCE_EXTENSION = /\.(?:cjs|js|mjs|ts|tsx)$/u;

let cachedArtifact: string | undefined;

export function resolveArtifact(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env[E2E_ARTIFACT_ENV]?.trim();
  if (!configured) {
    throw new Error(
      `${E2E_ARTIFACT_ENV} is required; run scripts/run-cli-e2e.sh or set it to the absolute packaged Runfree executable`,
    );
  }
  if (!path.isAbsolute(configured)) {
    throw new Error(`${E2E_ARTIFACT_ENV} must be an absolute path: ${configured}`);
  }
  if (SOURCE_EXTENSION.test(configured)) {
    throw new Error(`${E2E_ARTIFACT_ENV} must name a packaged executable, not source: ${configured}`);
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(configured);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${E2E_ARTIFACT_ENV} does not name a readable file: ${configured}: ${detail}`);
  }
  if (!stat.isFile()) {
    throw new Error(`${E2E_ARTIFACT_ENV} must name a file: ${configured}`);
  }
  if ((stat.mode & 0o111) === 0) {
    throw new Error(`${E2E_ARTIFACT_ENV} is not executable: ${configured}`);
  }
  return fs.realpathSync(configured);
}

export function artifactPath(): string {
  cachedArtifact ??= resolveArtifact();
  return cachedArtifact;
}
