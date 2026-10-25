// Spec 2026-10-24 google-service-account-source §4.1-§4.3: the pure core of the
// `google-service-account` source type. It checks the add-time flags, parses
// and checks the key JSON against the pinned client_email, and signs a
// self-signed RS256 JWT. It reads no file, runs no provider, and must not
// import admin-core.ts (admin-core imports this module).
//
// No message built here contains the key JSON, the PEM, a field value, or the
// `message` of a caught error (review M4): every refusal is a fixed string
// that names the field only.
import crypto from "node:crypto";

import { TokenResolutionError } from "../token-resolution.ts";

export const GOOGLE_SA_READ_ONLY_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly";
export const GOOGLE_SA_SCOPE_ALLOWLIST: readonly string[] = Object.freeze([
  GOOGLE_SA_READ_ONLY_SCOPE,
  "https://www.googleapis.com/auth/webmasters",
]);
export const GOOGLE_SA_TTL_MIN_SECONDS = 300;
export const GOOGLE_SA_TTL_MAX_SECONDS = 3600;
export const GOOGLE_SA_TTL_DEFAULT_SECONDS = 3300;
export const GOOGLE_SA_KEY_CACHE_MAX_AGE_MS = 4 * 60 * 60 * 1000;
export const GOOGLE_SA_CLIENT_EMAIL_RE = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
export const GOOGLE_SA_KEY_ID_RE = /^[0-9a-f]{40}$/;
const GOOGLE_SA_MIN_MODULUS_BITS = 2048;

/**
 * The pin refusal (§4.3). A caller that knows the source name passes it to
 * `googleServiceAccountFailure`, which substitutes it for `<name>`; the name
 * matches the source-name pattern, so it carries no control characters.
 */
function clientEmailMismatchMessage(sourceName = "<name>"): string {
  return `key JSON client_email does not match the pinned service account; run credential source add google-service-account ${sourceName} --replace-source to change it`;
}

const CLIENT_EMAIL_MISMATCH_CODE = "client-email-mismatch";

export type GoogleServiceAccountSource = {
  type: "google-service-account";
  keyJson: { source: "1password"; ref: string };
  clientEmail: string;
  scopes: string[];
  ttlSeconds: number;
  createdAt: string;
};

export type GoogleServiceAccountKey = { clientEmail: string; keyId: string; key: crypto.KeyObject };

/**
 * A key JSON refusal. Only this module constructs one, and only with a fixed
 * message, so the catch-all may show its message as is.
 */
export class GoogleServiceAccountKeyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "GoogleServiceAccountKeyError";
    this.code = code;
  }
}

function refuse(code: string, message: string): never {
  throw new GoogleServiceAccountKeyError(code, message);
}

/** Sorted, unique, non-empty, allowlisted; throws Error(fixed text) otherwise. Used by add-time and registry validation. */
export function normalizeGoogleServiceAccountScopes(values: readonly string[]): string[] {
  if (values.length === 0) throw new Error("google-service-account needs at least one --scope");
  for (const value of values) {
    if (!GOOGLE_SA_SCOPE_ALLOWLIST.includes(value)) {
      throw new Error(`--scope is not an allowed scope; allowed: ${GOOGLE_SA_SCOPE_ALLOWLIST.join(", ")}`);
    }
  }
  if (new Set(values).size !== values.length) throw new Error("--scope has a duplicate value");
  return [...values].sort();
}

export function assertGoogleServiceAccountTtl(seconds: number): void {
  if (!Number.isInteger(seconds) || seconds < GOOGLE_SA_TTL_MIN_SECONDS || seconds > GOOGLE_SA_TTL_MAX_SECONDS) {
    throw new Error(`--ttl must be a whole number of seconds from ${GOOGLE_SA_TTL_MIN_SECONDS} to ${GOOGLE_SA_TTL_MAX_SECONDS}`);
  }
}

/**
 * §4.3 steps 2-3. `pinnedClientEmail` is undefined only at first add.
 * Throws GoogleServiceAccountKeyError (fixed message) on any refusal.
 */
export function parseGoogleServiceAccountKeyJson(text: string, pinnedClientEmail: string | undefined): GoogleServiceAccountKey {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Node's JSON.parse message quotes part of the input (§4.3).
    return refuse("key-json-invalid", "key JSON is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return refuse("key-json-invalid", "key JSON is not a JSON object");
  }
  const record = parsed as Record<string, unknown>;
  const field = (name: string): string => {
    const value = record[name];
    if (typeof value !== "string") return refuse("key-json-field", `key JSON field ${name} is missing or not a string`);
    return value;
  };

  if (field("type") !== "service_account") refuse("key-json-field", "key JSON field type is not service_account");

  // The pattern runs before the pin compare and before any display (§4.2 review L4).
  const clientEmail = field("client_email");
  if (!GOOGLE_SA_CLIENT_EMAIL_RE.test(clientEmail)) {
    refuse("key-json-field", "key JSON field client_email is not a service account email");
  }
  if (pinnedClientEmail !== undefined && clientEmail !== pinnedClientEmail) {
    refuse(CLIENT_EMAIL_MISMATCH_CODE, clientEmailMismatchMessage());
  }

  const keyId = field("private_key_id");
  if (!GOOGLE_SA_KEY_ID_RE.test(keyId)) {
    refuse("key-json-field", "key JSON field private_key_id is not 40 lowercase hex characters");
  }

  const pem = field("private_key");
  // Refused before the parse: createPrivateKey would ask for a passphrase.
  if (pem.includes("ENCRYPTED PRIVATE KEY")) refuse("key-json-field", "key JSON field private_key is encrypted");
  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey(pem);
  } catch {
    return refuse("key-json-field", "key JSON field private_key is not a valid private key");
  }
  if (key.type !== "private") refuse("key-json-field", "key JSON field private_key is not a valid private key");
  if (key.asymmetricKeyType !== "rsa") refuse("key-json-field", "key JSON field private_key is not an RSA key");
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < GOOGLE_SA_MIN_MODULUS_BITS) {
    refuse("key-json-field", `key JSON field private_key is shorter than ${GOOGLE_SA_MIN_MODULUS_BITS} bits`);
  }

  if (record.universe_domain !== undefined && record.universe_domain !== "googleapis.com") {
    refuse("key-json-field", "key JSON field universe_domain is not googleapis.com");
  }

  return { clientEmail, keyId, key };
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** §4.3 step 4: a self-signed RS256 JWT with a `scope` claim and never `aud` (§3). */
export function signGoogleServiceAccountJwt(
  source: Pick<GoogleServiceAccountSource, "clientEmail" | "scopes" | "ttlSeconds">,
  key: Pick<GoogleServiceAccountKey, "keyId" | "key">,
  nowSeconds: number,
): string {
  const header = { typ: "JWT", alg: "RS256", kid: key.keyId };
  const payload = {
    iss: source.clientEmail,
    sub: source.clientEmail,
    scope: source.scopes.join(" "),
    iat: nowSeconds,
    exp: nowSeconds + source.ttlSeconds,
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  // RSA PKCS#1 v1.5 is Node's default padding for an RSA KeyObject.
  const signature = crypto.sign("sha256", Buffer.from(signingInput), key.key);
  const modulusBits = key.key.asymmetricKeyDetails?.modulusLength ?? 0;
  if (modulusBits === 0 || signature.length !== modulusBits / 8) {
    throw new Error("RS256 signing produced an unexpected signature length");
  }
  return `${signingInput}.${signature.toString("base64url")}`;
}

/**
 * The catch-all (§4.3, review M4): a TokenResolutionError (the 1Password read)
 * passes through unchanged; anything else becomes definitive with a fixed
 * message. The `message` of any other error is never read. `sourceName`, when
 * given, replaces `<name>` in the pin refusal's remedy.
 */
export function googleServiceAccountFailure(error: unknown, sourceName?: string): TokenResolutionError {
  if (error instanceof TokenResolutionError) return error;
  if (error instanceof GoogleServiceAccountKeyError) {
    return new TokenResolutionError({
      classification: "definitive",
      sourceKind: "google-service-account",
      code: error.code,
      safeMessage: error.code === CLIENT_EMAIL_MISMATCH_CODE ? clientEmailMismatchMessage(sourceName) : error.message,
    });
  }
  return new TokenResolutionError({
    classification: "definitive",
    sourceKind: "google-service-account",
    code: "sign-failed",
    safeMessage: "service account JWT signing failed",
  });
}
