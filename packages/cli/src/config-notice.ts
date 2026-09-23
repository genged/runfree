// Config-migration notice helpers shared by the CLI entrypoint and command
// modules. Kept out of `cli.ts` so command modules can use them without an
// import cycle (cli.ts -> commands/app.ts -> command modules -> here).

import type { ConfigMigrationNotice, ProjectInfo } from "./config.ts";
import { die } from "./errors.ts";

export function configMigrationText(migration: ConfigMigrationNotice): string {
  if (migration.fromVersion >= migration.toVersion) {
    return `.runfree/runfree.json uses removed legacy config keys; run \`runfree init\` to migrate`;
  }
  return `.runfree/runfree.json uses legacy config version ${migration.fromVersion}; run \`runfree init\` to migrate to version ${migration.toVersion}`;
}

export function configMigratedText(migration: ConfigMigrationNotice): string {
  if (migration.fromVersion >= migration.toVersion) {
    return "migrated .runfree/runfree.json to remove legacy config keys";
  }
  return `migrated .runfree/runfree.json from version ${migration.fromVersion} to ${migration.toVersion}`;
}

/** The migration success line plus every authority-preserving downgrade it made. */
export function configMigratedLines(migration: ConfigMigrationNotice): string[] {
  return [configMigratedText(migration), ...(migration.notes ?? [])];
}

export function assertConfigCurrent(project: ProjectInfo): void {
  if (!project.configMigration) return;
  die(configMigrationText(project.configMigration));
}
