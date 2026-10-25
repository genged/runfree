import crypto from "node:crypto";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";

import { TokenResolutionError } from "../token-resolution.ts";
import {
  assertGoogleServiceAccountTtl,
  GOOGLE_SA_KEY_CACHE_MAX_AGE_MS,
  GOOGLE_SA_SCOPE_ALLOWLIST,
  GOOGLE_SA_TTL_DEFAULT_SECONDS,
  GOOGLE_SA_TTL_MAX_SECONDS,
  GOOGLE_SA_TTL_MIN_SECONDS,
  GoogleServiceAccountKeyError,
  googleServiceAccountFailure,
  normalizeGoogleServiceAccountScopes,
  parseGoogleServiceAccountKeyJson,
  signGoogleServiceAccountJwt,
} from "./google-service-account.ts";

const EMAIL = "gsc-reader@my-project-123.iam.gserviceaccount.com";
const KEY_ID = "0123456789abcdef0123456789abcdef01234567";
const RO = "https://www.googleapis.com/auth/webmasters.readonly";
const RW = "https://www.googleapis.com/auth/webmasters";
const SENTINEL = "SENTINEL-7f3a91c2-do-not-print";
const MISMATCH =
  "key JSON client_email does not match the pinned service account; run credential source add google-service-account <name> --replace-source to change it";
let rsa: crypto.KeyPairKeyObjectResult;
let pem: string;
let pemBody: string;

function keyJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    type: "service_account",
    project_id: "my-project-123",
    private_key_id: KEY_ID,
    private_key: pem,
    client_email: EMAIL,
    client_id: "1",
    universe_domain: "googleapis.com",
    note: SENTINEL,
    ...overrides,
  });
}

function refusal(text: string, pin: string | undefined = EMAIL): GoogleServiceAccountKeyError {
  try {
    parseGoogleServiceAccountKeyJson(text, pin);
  } catch (error) {
    expect(error).toBeInstanceOf(GoogleServiceAccountKeyError);
    return error as GoogleServiceAccountKeyError;
  }
  throw new Error("expected a refusal");
}

function thrown(run: () => unknown): Error {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    return error as Error;
  }
  throw new Error("expected a refusal");
}

/** No refusal may echo the sentinel, the PEM body, or any extra value the test names. */
function expectSafe(error: Error, ...forbidden: string[]): void {
  const shown = `${error.message}\n${String(error.stack)}\n${String((error as { cause?: unknown }).cause ?? "")}`;
  expect(error.message).not.toContain(SENTINEL);
  expect(shown).not.toContain(SENTINEL);
  expect(shown).not.toContain(pemBody);
  expect(shown).not.toContain("PRIVATE KEY");
  for (const value of forbidden) expect(error.message).not.toContain(value);
}

beforeAll(() => {
  rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  pem = rsa.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  // A 64-character line from inside the base64 body.
  pemBody = pem.split("\n")[3] ?? "";
  expect(pemBody).toHaveLength(64);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("google-service-account constants (spec §4.1-§4.4)", () => {
  test("pin the allowlist, TTL bounds, and cache age", () => {
    expect(GOOGLE_SA_SCOPE_ALLOWLIST).toEqual([RO, RW]);
    expect([GOOGLE_SA_TTL_MIN_SECONDS, GOOGLE_SA_TTL_MAX_SECONDS, GOOGLE_SA_TTL_DEFAULT_SECONDS]).toEqual([300, 3600, 3300]);
    expect(GOOGLE_SA_KEY_CACHE_MAX_AGE_MS).toBe(14_400_000);
  });
});

describe("google-service-account flag checks (spec §4.2)", () => {
  test("refuses an empty scope list", () => {
    expect(thrown(() => normalizeGoogleServiceAccountScopes([])).message).toContain("--scope");
  });

  test("refuses a scope outside the allowlist without echoing it", () => {
    const scope = "https://www.googleapis.com/auth/cloud-platform";
    const error = thrown(() => normalizeGoogleServiceAccountScopes([RO, scope]));
    expect(error.message).toContain("--scope");
    expectSafe(error, scope, "cloud-platform");
    const control = `${RO}\u001b[31m${SENTINEL}`;
    expectSafe(thrown(() => normalizeGoogleServiceAccountScopes([control])), "\u001b");
  });

  test("refuses a duplicate scope", () => {
    const error = thrown(() => normalizeGoogleServiceAccountScopes([RO, RO]));
    expect(error.message).toContain("duplicate");
  });

  test("returns the scopes sorted", () => {
    expect(normalizeGoogleServiceAccountScopes([RO, RW])).toEqual([RW, RO]);
    expect(normalizeGoogleServiceAccountScopes([RO])).toEqual([RO]);
  });

  test.each([299, 3601, 300.5, 0, -1, Number.NaN, Number.POSITIVE_INFINITY])("refuses TTL %s", (seconds) => {
    expect(thrown(() => assertGoogleServiceAccountTtl(seconds)).message).toContain("--ttl");
  });

  test.each([300, 3600, GOOGLE_SA_TTL_DEFAULT_SECONDS])("accepts TTL %s", (seconds) => {
    expect(() => assertGoogleServiceAccountTtl(seconds)).not.toThrow();
  });
});

describe("google-service-account key JSON checks (spec §4.3)", () => {
  test("refuses text that is not JSON without echoing the input", () => {
    const error = refusal(`{"a": ${SENTINEL}`);
    expect(error.message).toBe("key JSON is not valid JSON");
    expect(error.code).toBe("key-json-invalid");
    expectSafe(error);
  });

  test.each(["[]", "null", '"text"', "42"])("refuses a non-object JSON value %s", (text) => {
    expect(refusal(text).message).toBe("key JSON is not a JSON object");
  });

  test("refuses a type other than service_account", () => {
    const error = refusal(keyJson({ type: "user" }));
    expect(error.message).toContain("field type");
    expectSafe(error, "user");
  });

  test.each(["type", "client_email", "private_key_id", "private_key"])("refuses a missing %s", (field) => {
    const error = refusal(keyJson({ [field]: undefined }));
    expect(error.message).toContain(`field ${field}`);
    expectSafe(error);
  });

  test.each([
    ["private_key_id", 1],
    ["client_email", ["a"]],
    ["private_key", { pem: SENTINEL }],
    ["type", null],
  ])("refuses a non-string %s", (field, value) => {
    const error = refusal(keyJson({ [field]: value }));
    expect(error.message).toContain(`field ${field}`);
    expectSafe(error);
  });

  test("refuses an EC key", () => {
    const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const error = refusal(keyJson({ private_key: ec.privateKey.export({ type: "pkcs8", format: "pem" }).toString() }));
    expect(error.message).toBe("key JSON field private_key is not an RSA key");
    expectSafe(error);
  });

  test("refuses an RSA key under 2048 bits", () => {
    const small = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
    const error = refusal(keyJson({ private_key: small.privateKey.export({ type: "pkcs8", format: "pem" }).toString() }));
    expect(error.message).toContain("field private_key");
    expect(error.message).toContain("2048 bits");
    expectSafe(error);
  });

  test("refuses an encrypted PEM before it is parsed", () => {
    const parse = vi.spyOn(crypto, "createPrivateKey");
    const encrypted = rsa.privateKey
      .export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "x" })
      .toString();
    const error = refusal(keyJson({ private_key: encrypted }));
    expect(error.message).toBe("key JSON field private_key is encrypted");
    expect(parse).not.toHaveBeenCalled();
    expectSafe(error, encrypted.split("\n")[3] ?? "");
  });

  test("the createPrivateKey spy sees a real parse", () => {
    const parse = vi.spyOn(crypto, "createPrivateKey");
    parseGoogleServiceAccountKeyJson(keyJson(), EMAIL);
    expect(parse).toHaveBeenCalledTimes(1);
  });

  test("refuses PEM bytes that do not parse without echoing them", () => {
    const error = refusal(keyJson({ private_key: `-----BEGIN PRIVATE KEY-----\n${SENTINEL}\n-----END PRIVATE KEY-----\n` }));
    expect(error.message).toBe("key JSON field private_key is not a valid private key");
    expectSafe(error);
  });

  test("refuses a public key in the private_key field", () => {
    const publicPem = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
    const error = refusal(keyJson({ private_key: publicPem }));
    expect(error.message).toContain("field private_key");
    expectSafe(error);
  });

  test.each(["ABC", KEY_ID.toUpperCase(), KEY_ID.slice(1), `${KEY_ID}0`, `${SENTINEL}`])("refuses private_key_id %s", (keyId) => {
    const error = refusal(keyJson({ private_key_id: keyId }));
    expect(error.message).toContain("field private_key_id");
    expectSafe(error, keyId);
  });

  test.each([
    "x@gmail.com",
    "123-compute@developer.gserviceaccount.com",
    "a\u001b[31m@b.iam.gserviceaccount.com",
    "GSC@my-project-123.iam.gserviceaccount.com",
    `${EMAIL}\n`,
  ])("refuses client_email %j", (email) => {
    const error = refusal(keyJson({ client_email: email }));
    expect(error.message).toContain("field client_email");
    expect(error.message).not.toContain("\u001b");
    expectSafe(error, email);
  });

  test("checks the client_email pattern before the pin", () => {
    const error = refusal(keyJson({ client_email: "a\u001b[31m@b.iam.gserviceaccount.com" }), EMAIL);
    expect(error.code).toBe("key-json-field");
  });

  test("refuses a universe_domain other than googleapis.com", () => {
    const error = refusal(keyJson({ universe_domain: "example.com" }));
    expect(error.message).toContain("field universe_domain");
    expectSafe(error, "example.com");
    expect(refusal(keyJson({ universe_domain: 1 })).message).toContain("field universe_domain");
  });

  test("accepts a key JSON without universe_domain", () => {
    expect(parseGoogleServiceAccountKeyJson(keyJson({ universe_domain: undefined }), EMAIL).keyId).toBe(KEY_ID);
  });

  test("refuses a client_email that differs from the pin", () => {
    const other = "other@my-project-123.iam.gserviceaccount.com";
    const error = refusal(keyJson({ client_email: other }), EMAIL);
    expect(error.message).toBe(MISMATCH);
    expect(error.code).toBe("client-email-mismatch");
    expectSafe(error, other, EMAIL);
  });

  test("without a pin (add time) returns the email, key id, and an RSA key", () => {
    const parsed = parseGoogleServiceAccountKeyJson(keyJson(), undefined);
    expect(parsed.clientEmail).toBe(EMAIL);
    expect(parsed.keyId).toBe(KEY_ID);
    expect(parsed.key.type).toBe("private");
    expect(parsed.key.asymmetricKeyType).toBe("rsa");
    expect(Object.keys(parsed).sort()).toEqual(["clientEmail", "key", "keyId"]);
  });

  test("accepts a PKCS#1 RSA PEM", () => {
    const pkcs1 = rsa.privateKey.export({ type: "pkcs1", format: "pem" }).toString();
    expect(parseGoogleServiceAccountKeyJson(keyJson({ private_key: pkcs1 }), EMAIL).key.asymmetricKeyType).toBe("rsa");
  });
});

describe("google-service-account RS256 signing (spec §3, §4.3 step 4)", () => {
  function decode(jwt: string): { header: unknown; payload: Record<string, unknown>; verified: boolean } {
    const [h, p, s] = jwt.split(".");
    if (h === undefined || p === undefined || s === undefined) throw new Error("not a JWT");
    return {
      header: JSON.parse(Buffer.from(h, "base64url").toString()),
      payload: JSON.parse(Buffer.from(p, "base64url").toString()),
      verified: crypto.verify("sha256", Buffer.from(`${h}.${p}`), rsa.publicKey, Buffer.from(s, "base64url")),
    };
  }

  test("signs an RS256 self-signed JWT that verifies with the public key", () => {
    const parsed = parseGoogleServiceAccountKeyJson(keyJson(), EMAIL);
    const jwt = signGoogleServiceAccountJwt({ clientEmail: EMAIL, scopes: [RO], ttlSeconds: 3300 }, parsed, 1_700_000_000);
    expect(jwt.split(".")).toHaveLength(3);
    const { header, payload, verified } = decode(jwt);
    expect(verified).toBe(true);
    expect(header).toEqual({ typ: "JWT", alg: "RS256", kid: KEY_ID });
    expect(payload).toEqual({ iss: EMAIL, sub: EMAIL, scope: RO, iat: 1_700_000_000, exp: 1_700_003_300 });
    expect(payload).not.toHaveProperty("aud");
    expect(jwt).not.toContain(SENTINEL);
  });

  test("joins two scopes with one space in sorted order", () => {
    const parsed = parseGoogleServiceAccountKeyJson(keyJson(), EMAIL);
    const scopes = normalizeGoogleServiceAccountScopes([RO, RW]);
    const { payload } = decode(signGoogleServiceAccountJwt({ clientEmail: EMAIL, scopes, ttlSeconds: 300 }, parsed, 10));
    expect(payload.scope).toBe(`${RW} ${RO}`);
    expect(payload.exp).toBe(310);
  });

  test("an unexpected signature length is an error without key material", () => {
    const parsed = parseGoogleServiceAccountKeyJson(keyJson(), EMAIL);
    vi.spyOn(crypto, "sign").mockImplementation((() => Buffer.alloc(64)) as unknown as typeof crypto.sign);
    const error = thrown(() => signGoogleServiceAccountJwt({ clientEmail: EMAIL, scopes: [RO], ttlSeconds: 300 }, parsed, 10));
    expect(error.message).toBe("RS256 signing produced an unexpected signature length");
    expectSafe(error);
  });
});

describe("google-service-account catch-all (spec §4.3, review M4)", () => {
  test("an unknown error becomes definitive with a fixed message", () => {
    const error = googleServiceAccountFailure(new Error(`${SENTINEL} ${pem}`));
    expect(error).toBeInstanceOf(TokenResolutionError);
    expect(error.classification).toBe("definitive");
    expect(error.sourceKind).toBe("google-service-account");
    expect(error.code).toBe("sign-failed");
    expect(error.safeMessage).toBe("service account JWT signing failed");
    expectSafe(error);
  });

  test("a non-Error value becomes definitive with a fixed message", () => {
    const error = googleServiceAccountFailure(SENTINEL);
    expect(error.classification).toBe("definitive");
    expectSafe(error);
  });

  test("the real JSON.parse failure is mapped without its message", () => {
    let raw: unknown;
    try {
      JSON.parse(`{"a": ${SENTINEL}`);
    } catch (error) {
      raw = error;
    }
    const error = googleServiceAccountFailure(raw);
    expect(error.safeMessage).toBe("service account JWT signing failed");
    expectSafe(error);
  });

  test("a key check refusal keeps its fixed message and becomes definitive", () => {
    const error = googleServiceAccountFailure(refusal(keyJson({ client_email: "other@my-project-123.iam.gserviceaccount.com" })));
    expect(error.classification).toBe("definitive");
    expect(error.sourceKind).toBe("google-service-account");
    expect(error.code).toBe("client-email-mismatch");
    expect(error.message).toBe(MISMATCH);
    expect(error.safeMessage).toBe(MISMATCH);
  });

  test("a TokenResolutionError passes through unchanged", () => {
    const transient = new TokenResolutionError({ classification: "transient", sourceKind: "1password", code: "op-locked", safeMessage: "1Password is locked" });
    expect(googleServiceAccountFailure(transient)).toBe(transient);
    const definitive = new TokenResolutionError({ classification: "definitive", sourceKind: "1password", code: "op-not-found", safeMessage: "item not found" });
    expect(googleServiceAccountFailure(definitive)).toBe(definitive);
  });

  test("an error that only carries a code is not treated as a key check refusal", () => {
    // The catch-all trusts only the fixed messages this module constructs.
    const error = googleServiceAccountFailure(Object.assign(new Error(SENTINEL), { code: "key-json-field" }));
    expect(error.code).toBe("sign-failed");
    expectSafe(error);
  });
});
