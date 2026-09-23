// Named credential source typed intents + enforcement (split from options.ts).
// Shared source-registry and store machinery lives in admin-core.ts.

import fs from "node:fs";
import path from "node:path";
import {
  runfreeConfigRoot,
} from "../paths.ts";
import {
  assertKnownSourceName,
  assertSourceArgumentsOutsideProject,
  childEnv,
  type CommandSource,
  die,
  ensureStateDirs,
  formatDurationSeconds,
  type JwtAlgorithm,
  type JwtSource,
  loadSourceRegistry,
  type NamedSource,
  parseDurationSeconds,
  parseTokenSourceConfig,
  policyJson,
  readJsonFile,
  regularExecutableRealpath,
  resolveHostExecutable,
  runCommandSource,
  signJwtSource,
  type SourceAddCommandInput,
  type SourceAddJwtInput,
  sourceConfigPath,
  type SourceNameInput,
  type SourceRegistry,
  writeJsonFile,
} from "./admin-core.ts";

function saveSourceRegistry(registry: SourceRegistry): void {
  writeJsonFile(sourceConfigPath(), registry, 0o600);
}

function resolveCommandExecutable(command: string): string {
  if (command.trim() === "") die("credential source add requires a command");
  if (command.includes("/") || path.isAbsolute(command)) {
    const realPath = regularExecutableRealpath(command);
    if (!realPath) die(`${command} executable must be an executable regular file outside the project`);
    return realPath;
  }

  const realPath = resolveHostExecutable(command);
  if (realPath) return realPath;
  die(`${command} executable was not found on the sanitized host PATH`);
}

function commandDisplay(source: CommandSource): string {
  return source.displayArgv.join(" ");
}

function commandSourcesEqual(left: CommandSource, right: CommandSource): boolean {
  return left.type === right.type
    && left.argv.length === right.argv.length
    && left.argv.every((entry, index) => entry === right.argv[index])
    && left.displayArgv.length === right.displayArgv.length
    && left.displayArgv.every((entry, index) => entry === right.displayArgv[index]);
}

function namedSourcesEqual(left: NamedSource, right: NamedSource): boolean {
  if (left.type !== right.type) return false;
  if (left.type === "command" && right.type === "command") return commandSourcesEqual(left, right);
  if (left.type === "jwt" && right.type === "jwt") {
    return left.alg === right.alg
      && left.privateKey.source === right.privateKey.source
      && left.privateKey.ref === right.privateKey.ref
      && left.ttlSeconds === right.ttlSeconds
      && policyJson(left.headers) === policyJson(right.headers)
      && policyJson(left.claims) === policyJson(right.claims);
  }
  return false;
}

function sourceUsers(registryName: string): string[] {
  const users: string[] = [];
  const projectsDir = path.join(runfreeConfigRoot(childEnv()), "projects");
  let projectDirs: string[] = [];
  try {
    projectDirs = fs.readdirSync(projectsDir).map((entry) => path.join(projectsDir, entry));
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return users;
    throw error;
  }
  for (const dir of projectDirs) {
    let stat: fs.Stats;
    try {
      stat = fs.statSync(dir);
    } catch {
      continue;
    }
    if (!stat.isDirectory()) continue;
    const config = parseTokenSourceConfig(readJsonFile<unknown>(path.join(dir, "tokens.json"), {}), path.join(dir, "tokens.json"));
    for (const [tokenName, source] of Object.entries(config)) {
      if (source.source === "named" && source.name === registryName) users.push(tokenName);
    }
  }
  return Array.from(new Set(users)).sort();
}

function parseKeyValueOption(flag: string, value: string): { key: string; value: string } {
  const index = value.indexOf("=");
  if (index <= 0) die(`${flag} must be key=value`);
  const key = value.slice(0, index);
  const parsedValue = value.slice(index + 1);
  if (!/^[A-Za-z0-9_.-]+$/.test(key)) die(`${flag} key must contain only letters, numbers, dot, underscore, or hyphen`);
  if (parsedValue === "") die(`${flag} value must be non-empty`);
  return { key, value: parsedValue };
}

function putUniqueKeyValue(target: Record<string, string>, flag: string, raw: string): void {
  const { key, value } = parseKeyValueOption(flag, raw);
  if (Object.hasOwn(target, key)) die(`${flag} ${key} was provided more than once`);
  target[key] = value;
}

function sourceTypeDisplay(source: NamedSource): string {
  return source.type;
}

function jwtDisplay(source: JwtSource): string[] {
  const lines = [
    `alg: ${source.alg}`,
    "private key: 1password",
    `ttl: ${formatDurationSeconds(source.ttlSeconds)}`,
  ];
  for (const [key, value] of Object.entries(source.headers).sort(([left], [right]) => left.localeCompare(right))) {
    lines.push(`header: ${key}=${value}`);
  }
  for (const [key, value] of Object.entries(source.claims).sort(([left], [right]) => left.localeCompare(right))) {
    lines.push(`claim: ${key}=${value}`);
  }
  return lines;
}

// Typed enforcement for `runfree credential source add jwt <name> ...`. Re-validates the
// algorithm, 1Password key reference, TTL, and generated-claim/header rules,
// signs once to verify, and stores the source.
export function sourceAddJwtIntent(input: SourceAddJwtInput): void {
  const { name } = input;
  if (!name) die("usage: runfree credential source add jwt <name> [--replace-source] --alg ES256 --private-key-from-1password op://... --claim key=value [--header key=value]... --ttl 19m");
  assertKnownSourceName(name);

  const algValue = singleJwtOption(input.alg, "--alg");
  const privateKeyRef = singleJwtOption(input.privateKeyRef, "--private-key-from-1password");
  const ttlValue = singleJwtOption(input.ttl, "--ttl");

  if (algValue === undefined) die("credential source add jwt requires --alg ES256");
  if (algValue !== "ES256") die("--alg must be ES256");
  const alg: JwtAlgorithm = algValue;
  if (!privateKeyRef) die("credential source add jwt requires --private-key-from-1password op://...");
  if (!privateKeyRef.startsWith("op://")) die("1Password references must start with op://");
  if (!ttlValue) die("credential source add jwt requires --ttl <duration>");
  const ttlSeconds = parseDurationSeconds(ttlValue, "--ttl");

  const headers: Record<string, string> = {};
  for (const raw of input.headers) {
    const { key } = parseKeyValueOption("--header", raw);
    if (key === "alg") die("--header alg is generated from --alg");
    putUniqueKeyValue(headers, "--header", raw);
  }
  const claims: Record<string, string> = {};
  for (const raw of input.claims) {
    const { key } = parseKeyValueOption("--claim", raw);
    if (key === "iat" || key === "exp") die(`--claim ${key} is generated from --ttl`);
    putUniqueKeyValue(claims, "--claim", raw);
  }

  ensureStateDirs();
  const source: JwtSource = {
    type: "jwt",
    alg,
    privateKey: { source: "1password", ref: privateKeyRef },
    headers,
    claims,
    ttlSeconds,
    createdAt: new Date().toISOString(),
  };
  const registry = loadSourceRegistry();
  const existing = registry[name];
  if (existing && namedSourcesEqual(existing, source)) {
    console.log(`${name} source unchanged`);
    console.log(`type: ${sourceTypeDisplay(existing)}`);
    const details = existing.type === "jwt"
      ? jwtDisplay(existing)
      : [`command: ${commandDisplay(existing)}`];
    for (const line of details) console.log(line);
    console.log("agent exposure: no");
    return;
  }
  if (existing && !input.replaceSource) {
    const users = sourceUsers(name);
    die(`${name} source is already configured; pass --replace-source to change it${users.length > 0 ? `; used by credential bindings: ${users.join(", ")}` : ""}`);
  }
  try {
    signJwtSource(source);
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
  registry[name] = source;
  saveSourceRegistry(registry);
  console.log(`${name} source ${existing ? "replaced" : "configured"}`);
  console.log("type: jwt");
  for (const line of jwtDisplay(source)) console.log(line);
  console.log("agent exposure: no");
}

// Typed enforcement for `runfree credential source add <name> -- <command>`. The yargs
// front-end performs the `--` split and passes the command tokens verbatim; this
// re-validates the source name and command, runs the host executable safety
// checks, executes the source once to verify it, and stores it.
export function sourceAddCommandIntent(input: SourceAddCommandInput): void {
  const { name } = input;
  if (!name) die("usage: runfree credential source add <name> [--replace-source] -- <command> [args...]");
  assertKnownSourceName(name);
  const displayArgv = input.command;
  if (displayArgv.length === 0) die("credential source add requires a command");

  ensureStateDirs();
  const executable = resolveCommandExecutable(displayArgv[0]);
  assertSourceArgumentsOutsideProject(displayArgv.slice(1));
  const source: CommandSource = {
    type: "command",
    argv: [executable, ...displayArgv.slice(1)],
    displayArgv,
    createdAt: new Date().toISOString(),
  };
  const registry = loadSourceRegistry();
  const existing = registry[name];
  if (existing && namedSourcesEqual(existing, source)) {
    console.log(`${name} source unchanged`);
    console.log(`type: command`);
    console.log(`command: ${commandDisplay(source)}`);
    console.log("agent exposure: no");
    return;
  }
  if (existing && !input.replaceSource) {
    const users = sourceUsers(name);
    die(`${name} source is already configured; pass --replace-source to change it${users.length > 0 ? `; used by credential bindings: ${users.join(", ")}` : ""}`);
  }
  try {
    runCommandSource(source);
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
  registry[name] = source;
  saveSourceRegistry(registry);
  console.log(`${name} source ${existing ? "replaced" : "configured"}`);
  console.log(`type: command`);
  console.log(`command: ${commandDisplay(source)}`);
  console.log("agent exposure: no");
}

function singleJwtOption(value: string | string[] | undefined, flag: string): string | undefined {
  if (Array.isArray(value)) {
    if (value.length > 1) die(`${flag} may only be given once`);
    return value[0];
  }
  return value;
}

export function sourceList(): void {
  for (const name of Object.keys(loadSourceRegistry()).sort()) console.log(name);
}

export function sourceShowIntent(input: SourceNameInput): void {
  assertKnownSourceName(input.name);
  const source = loadSourceRegistry()[input.name];
  if (!source) die(`unknown source: ${input.name}`);
  const users = sourceUsers(input.name);
  console.log(`${input.name}: configured`);
  console.log(`type: ${sourceTypeDisplay(source)}`);
  if (source.type === "command") {
    console.log(`command: ${commandDisplay(source)}`);
  } else {
    for (const line of jwtDisplay(source)) console.log(line);
  }
  console.log(`used by: ${users.join(", ") || "none"}`);
  console.log("agent exposure: no");
  console.log("executes during: credential sync");
}

export function sourceRemoveIntent(input: SourceNameInput): void {
  assertKnownSourceName(input.name);
  const registry = loadSourceRegistry();
  if (!registry[input.name]) die(`unknown source: ${input.name}`);
  const users = sourceUsers(input.name);
  if (users.length > 0) die(`${input.name} is used by credential bindings: ${users.join(", ")}`);
  delete registry[input.name];
  saveSourceRegistry(registry);
  console.log(`${input.name} source removed`);
}
