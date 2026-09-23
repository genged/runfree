import path from "node:path";

import { sha256Hex } from "./strict-primitives.ts";

export type ProjectIdentity = {
  name: string;
  containerRoot: string;
  compatRoot: "/workspace";
};

type ProjectIdentityConfig = {
  project?: {
    name?: string;
  };
};

const COMPAT_ROOT = "/workspace";
const PROJECT_NAME_LIMIT = 64;

export function projectHash(projectRoot: string): string {
  return sha256Hex(projectRoot).slice(0, 12);
}

export function composeProjectName(projectRoot: string): string {
  return `runfree-${projectHash(projectRoot)}`;
}

export function sanitizeProjectName(input: string): string {
  const sanitized = input
    .trim()
    .replace(/\s+/g, "-")
    .replace(/[\\/\x00-\x1F\x7F"'`$&;|<>(){}\[\]*?!:#]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[.-]+/, "")
    .slice(0, PROJECT_NAME_LIMIT)
    .replace(/[.-]+$/, "");
  return sanitized || "project";
}

export function projectIdentity(projectRoot: string, config: ProjectIdentityConfig = {}): ProjectIdentity {
  const sourceName = config.project?.name ?? (path.basename(path.resolve(projectRoot)) || "project");
  const name = sanitizeProjectName(sourceName);
  return {
    name,
    containerRoot: `/workspaces/${name}`,
    compatRoot: COMPAT_ROOT,
  };
}
