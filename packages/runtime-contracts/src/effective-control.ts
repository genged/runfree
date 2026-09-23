
import fs from "node:fs";
import path from "node:path";

import {
  validateNetworkPolicy,
  type LoadedNetworkPolicy,
} from "./network-policy.js";
import {
  validateOAuthMediationPolicy,
  type LoadedOAuthMediationPolicy,
} from "./oauth-mediation-policy.js";
import { sha256Digest as sha256 } from "./primitives.js";

export const EFFECTIVE_CONTROL_SCHEMA_VERSION = 1 as const;
export const EFFECTIVE_CONTROL_COMPILER_VERSION = "desired-policy-v2-1" as const;
export const DEFAULT_EFFECTIVE_PROXY_ROOT = "/app/runfree-effective";
const MAX_CONTROL_FILE_BYTES = 1024 * 1024;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PROXY_PAYLOAD_NAMES = ["network-policy.json", "oauth-mediation-policy.json"] as const;

type ProxyPayloadName = typeof PROXY_PAYLOAD_NAMES[number];

export type ActiveEffectiveControlSelection = {
  schemaVersion: typeof EFFECTIVE_CONTROL_SCHEMA_VERSION;
  controlGeneration: string;
  proxyManifestDigest: string;
  hostManifestDigest: string;
};

export type EffectiveProxyManifest = {
  schemaVersion: typeof EFFECTIVE_CONTROL_SCHEMA_VERSION;
  compilerVersion: typeof EFFECTIVE_CONTROL_COMPILER_VERSION;
  controlGeneration: string;
  policyGeneration: string;
  files: Record<ProxyPayloadName, string>;
};

export type LoadedEffectiveProxyControl = {
  active: ActiveEffectiveControlSelection;
  manifest: EffectiveProxyManifest;
  networkPolicy: LoadedNetworkPolicy;
  networkPolicyPath: string;
  oauthPolicy: LoadedOAuthMediationPolicy;
  oauthPolicyPath: string;
};


function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} fields are malformed`);
  }
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) throw new Error(`${label} is malformed`);
  return value;
}

// Control files are tiny machine contracts. This parser rejects duplicate
// decoded object keys, excessive nesting, non-finite numbers, and JSON syntax
// extensions so a producer and consumer cannot interpret authority differently.
function parseStrictJson(source: string, maxDepth = 64): unknown {
  let offset = 0;
  const fail = (message: string): never => {
    throw new Error(`invalid strict JSON at byte ${Buffer.byteLength(source.slice(0, offset))}: ${message}`);
  };
  const whitespace = (): void => {
    while (offset < source.length && " \t\r\n".includes(source[offset] ?? "")) offset += 1;
  };
  const string = (): string => {
    const start = offset;
    if (source[offset] !== '"') fail("expected string");
    offset += 1;
    while (offset < source.length) {
      const character = source[offset];
      if (character === '"') {
        offset += 1;
        let parsed: unknown;
        try {
          parsed = JSON.parse(source.slice(start, offset)) as unknown;
        } catch {
          return fail("malformed string");
        }
        if (typeof parsed !== "string") return fail("expected string");
        return parsed;
      }
      if (character === "\\") offset += 2;
      else {
        if ((character?.codePointAt(0) ?? 0) < 0x20) fail("unescaped control character");
        offset += 1;
      }
    }
    return fail("unterminated string");
  };
  const value = (depth: number): unknown => {
    whitespace();
    if (depth > maxDepth) fail(`nesting exceeds ${maxDepth}`);
    const character = source[offset];
    if (character === '"') return string();
    if (character === "{") {
      offset += 1;
      whitespace();
      const result: Record<string, unknown> = {};
      const keys = new Set<string>();
      if (source[offset] === "}") {
        offset += 1;
        return result;
      }
      while (offset < source.length) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail(`duplicate object key ${JSON.stringify(key)}`);
        keys.add(key);
        whitespace();
        if (source[offset] !== ":") fail("expected colon");
        offset += 1;
        Object.defineProperty(result, key, {
          value: value(depth + 1),
          configurable: true,
          enumerable: true,
          writable: true,
        });
        whitespace();
        if (source[offset] === "}") {
          offset += 1;
          return result;
        }
        if (source[offset] !== ",") fail("expected comma");
        offset += 1;
      }
      return fail("unterminated object");
    }
    if (character === "[") {
      offset += 1;
      whitespace();
      const result: unknown[] = [];
      if (source[offset] === "]") {
        offset += 1;
        return result;
      }
      while (offset < source.length) {
        result.push(value(depth + 1));
        whitespace();
        if (source[offset] === "]") {
          offset += 1;
          return result;
        }
        if (source[offset] !== ",") fail("expected comma");
        offset += 1;
      }
      return fail("unterminated array");
    }
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]] as const) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length;
        return parsed;
      }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(offset))?.[0];
    if (number !== undefined) {
      offset += number.length;
      const parsed = JSON.parse(number) as number;
      if (!Number.isFinite(parsed)) fail("number is outside the finite range");
      return parsed;
    }
    return fail("expected value");
  };
  const parsed = value(0);
  whitespace();
  if (offset !== source.length) fail("unexpected trailing content");
  return parsed;
}

function readRegularFile(filePath: string, label: string): string {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error(`${label} is not a regular single-link file`);
  }
  if (stat.size > MAX_CONTROL_FILE_BYTES) throw new Error(`${label} exceeds ${MAX_CONTROL_FILE_BYTES} bytes`);
  return fs.readFileSync(filePath, "utf8");
}

function assertGenerationDirectory(root: string, controlGeneration: string): string {
  const directory = path.join(root, "generations", controlGeneration.slice("sha256:".length));
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("selected effective generation is not a regular directory");
  }
  return directory;
}

function parseActive(source: string): ActiveEffectiveControlSelection {
  const raw = record(parseStrictJson(source), "active effective control selection");
  exactKeys(raw, ["schemaVersion", "controlGeneration", "proxyManifestDigest", "hostManifestDigest"], "active effective control selection");
  if (raw.schemaVersion !== EFFECTIVE_CONTROL_SCHEMA_VERSION) throw new Error("active effective control schema version is unsupported");
  return {
    schemaVersion: EFFECTIVE_CONTROL_SCHEMA_VERSION,
    controlGeneration: digest(raw.controlGeneration, "active control generation"),
    proxyManifestDigest: digest(raw.proxyManifestDigest, "active proxy manifest digest"),
    hostManifestDigest: digest(raw.hostManifestDigest, "active host manifest digest"),
  };
}

function parseManifest(source: string): EffectiveProxyManifest {
  const raw = record(parseStrictJson(source), "effective proxy manifest");
  exactKeys(raw, ["schemaVersion", "compilerVersion", "controlGeneration", "policyGeneration", "files"], "effective proxy manifest");
  if (raw.schemaVersion !== EFFECTIVE_CONTROL_SCHEMA_VERSION) throw new Error("effective proxy manifest schema version is unsupported");
  if (raw.compilerVersion !== EFFECTIVE_CONTROL_COMPILER_VERSION) throw new Error("effective proxy manifest compiler version is unsupported");
  const files = record(raw.files, "effective proxy manifest files");
  exactKeys(files, PROXY_PAYLOAD_NAMES, "effective proxy manifest files");
  return {
    schemaVersion: EFFECTIVE_CONTROL_SCHEMA_VERSION,
    compilerVersion: EFFECTIVE_CONTROL_COMPILER_VERSION,
    controlGeneration: digest(raw.controlGeneration, "manifest control generation"),
    policyGeneration: digest(raw.policyGeneration, "manifest policy generation"),
    files: {
      "network-policy.json": digest(files["network-policy.json"], "network policy digest"),
      "oauth-mediation-policy.json": digest(files["oauth-mediation-policy.json"], "OAuth policy digest"),
    },
  };
}

export function effectiveProxyRootFromEnv(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const root = env.RUNFREE_EFFECTIVE_PROXY_ROOT;
  return typeof root === "string" && root.trim() !== "" ? root : undefined;
}

export function loadEffectiveProxyControl(root = effectiveProxyRootFromEnv() ?? DEFAULT_EFFECTIVE_PROXY_ROOT): LoadedEffectiveProxyControl {
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error("effective proxy root is not a directory");
  const activePath = path.join(root, "active.json");
  const activeSource = readRegularFile(activePath, "active effective control selection");
  const active = parseActive(activeSource);
  const generationDirectory = assertGenerationDirectory(root, active.controlGeneration);
  const manifestPath = path.join(generationDirectory, "manifest.json");
  const manifestSource = readRegularFile(manifestPath, "effective proxy manifest");
  if (sha256(manifestSource) !== active.proxyManifestDigest) throw new Error("selected proxy manifest digest does not match active selection");
  const manifest = parseManifest(manifestSource);
  if (manifest.controlGeneration !== active.controlGeneration) throw new Error("selected proxy manifest names a different control generation");

  const networkPolicyPath = path.join(generationDirectory, "network-policy.json");
  const oauthPolicyPath = path.join(generationDirectory, "oauth-mediation-policy.json");
  const networkSource = readRegularFile(networkPolicyPath, "effective network policy");
  const oauthSource = readRegularFile(oauthPolicyPath, "effective OAuth policy");
  if (sha256(networkSource) !== manifest.files["network-policy.json"]
    || sha256(oauthSource) !== manifest.files["oauth-mediation-policy.json"]) {
    throw new Error("selected effective proxy payload digest does not match its manifest");
  }
  const networkPolicy = validateNetworkPolicy(parseStrictJson(networkSource), networkPolicyPath);
  if (networkPolicy.generation !== manifest.policyGeneration) throw new Error("selected network policy generation does not match its manifest");
  const oauthPolicy = validateOAuthMediationPolicy(parseStrictJson(oauthSource), oauthPolicyPath);

  // The pointer is the only mutable selector. If it changed while the immutable
  // files were read, reject this attempt; the next level-triggered poll loads
  // the new selection from the start instead of reporting a mixed snapshot.
  if (readRegularFile(activePath, "active effective control selection") !== activeSource) {
    throw new Error("active effective control selection changed while loading");
  }
  return { active, manifest, networkPolicy, networkPolicyPath, oauthPolicy, oauthPolicyPath };
}
